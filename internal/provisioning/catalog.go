package provisioning

import (
	"context"
	"net/http"
	"strings"
)

// CheckConnection asks the application's SCIM endpoint who it is
// (/ServiceProviderConfig), with the token the Hub sends it: nil when the
// endpoint answers and accepts the token.
func CheckConnection(ctx context.Context, baseURL, token string) error {
	var out map[string]any
	return newSCIMClient().do(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/ServiceProviderConfig", token, nil, &out)
}

// Catalog is what an application says it can give: its permissions, and
// its roles with the permissions each carries.
type Catalog struct {
	Permissions []CatalogPermission `json:"permissions"`
	Roles       []CatalogRole       `json:"roles"`
}

type CatalogPermission struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type CatalogRole struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// FetchCatalog reads the application's roles and permissions from
// <SCIM endpoint>/Hub/Catalog, which an application offers so the Hub can
// import them (the PM tool does).
func FetchCatalog(ctx context.Context, baseURL, token string) (Catalog, error) {
	var out Catalog
	err := newSCIMClient().do(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/Hub/Catalog", token, nil, &out)
	return out, err
}
