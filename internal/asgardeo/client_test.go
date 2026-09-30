package asgardeo

import (
	"context"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeit26/identity-hub/internal/testfakes"
)

func TestParseUserVariants(t *testing.T) {
	u, err := parseUser([]byte(`{"id":"1","userName":"DEFAULT/Ada@X.io",
		"emails":[{"value":"other@x.io"},{"value":"Ada@X.io","primary":true}],
		"urn:scim:wso2:schema":{"accountLocked":"true","userAccountType":"Customer"}}`))
	if err != nil || u.Email != "ada@x.io" || !u.Locked || !u.InUserStore() {
		t.Fatalf("object emails: %+v %v", u, err)
	}
	u, _ = parseUser([]byte(`{"id":"2","userName":"owner@x.io","emails":["Owner@x.io"],
		"urn:scim:wso2:schema":{"accountLocked":false,"userAccountType":"Owner"}}`))
	if u.Email != "owner@x.io" || u.Locked || u.InUserStore() || u.AccountType != "Owner" {
		t.Fatalf("string emails: %+v", u)
	}
	u, _ = parseUser([]byte(`{"id":"3","userName":"DEFAULT/bo@x.io","urn:scim:wso2:schema":{"accountState":"LOCKED"}}`))
	if u.Email != "bo@x.io" || !u.Locked {
		t.Fatalf("fallbacks: %+v", u)
	}
}

func newClient(t *testing.T) (*Client, *testfakes.Asgardeo) {
	fake := testfakes.NewAsgardeo()
	srv := httptest.NewServer(fake.Handler())
	t.Cleanup(srv.Close)
	fake.BaseURL = srv.URL
	return New(srv.URL, fake.M2MClientID, fake.M2MClientSecret), fake
}

func TestListUsersReadsEveryPage(t *testing.T) {
	c, fake := newClient(t)
	for i := range 250 {
		fake.AddUser(testfakes.AsgardeoUser{Email: "u" + strconv.Itoa(i) + "@x.io"})
	}
	users, err := c.ListUsers(context.Background())
	if err != nil || len(users) != 250 {
		t.Fatalf("got %d users, %v", len(users), err)
	}
}

func TestCreateUserExisting(t *testing.T) {
	c, fake := newClient(t)
	id := fake.AddUser(testfakes.AsgardeoUser{Email: "ada@x.io"})
	u, created, err := c.CreateUser(context.Background(), "Ada", "", "ada@x.io")
	if err != nil || created || u.ID != id {
		t.Fatalf("got %+v created=%v err=%v", u, created, err)
	}
	u, created, err = c.CreateUser(context.Background(), "Bo", "B", "bo@x.io")
	if err != nil || !created || !fake.User(u.ID).Invited {
		t.Fatalf("new user: %+v created=%v err=%v", u, created, err)
	}
}

// Asgardeo creates the account but answers too late: it is found and
// reported as created, not as a failure (and a retry would not duplicate it).
func TestCreateUserUnanswered(t *testing.T) {
	c, fake := newClient(t)
	c.writeTimeout = 200 * time.Millisecond
	fake.SlowCreate = time.Second
	u, created, err := c.CreateUser(context.Background(), "Cy", "", "cy@x.io")
	if err != nil || !created || u == nil || u.Email != "cy@x.io" {
		t.Fatalf("got %+v created=%v err=%v", u, created, err)
	}
}

// No answer and no account: a clear, retryable failure.
func TestCreateUserUnansweredNothingMade(t *testing.T) {
	c, fake := newClient(t)
	c.writeTimeout = 200 * time.Millisecond
	fake.SlowCreate = time.Second
	fake.DropCreates = true
	_, _, err := c.CreateUser(context.Background(), "Cy", "", "cy@x.io")
	var ae *Error
	if !errors.As(err, &ae) || !ae.Unanswered || !strings.Contains(ae.Detail, "safe to try again") {
		t.Fatalf("err = %v", err)
	}
}

func TestGroupsNeedAuthorization(t *testing.T) {
	c, fake := newClient(t)
	if c.CanManageGroups(context.Background()) {
		t.Fatal("groups reported usable without the scopes")
	}
	fake.GroupsAuthorized = true
	c2 := New(fake.BaseURL, fake.M2MClientID, fake.M2MClientSecret)
	if !c2.CanManageGroups(context.Background()) {
		t.Fatal("groups not usable with the scopes")
	}
}

func TestWrongCredentials(t *testing.T) {
	_, fake := newClient(t)
	c := New(fake.BaseURL, "m2m-client", "wrong")
	_, err := c.ListUsers(context.Background())
	if !IsStatus(err, 401) {
		t.Fatalf("err = %v", err)
	}
}
