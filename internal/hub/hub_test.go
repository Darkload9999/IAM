package hub

import "testing"

func TestNormalEmail(t *testing.T) {
	for in, ok := range map[string]bool{
		" Ada@Zeit26.com ": true, "ada@zeit26": false, "Ada <ada@x.io>": false, "": false, "a@b.co": true,
	} {
		_, err := normalEmail(in)
		if (err == nil) != ok {
			t.Errorf("normalEmail(%q): err = %v", in, err)
		}
	}
	if got, _ := normalEmail(" Ada@Zeit26.com "); got != "ada@zeit26.com" {
		t.Errorf("not lowercased: %q", got)
	}
}

func TestAppInputValidation(t *testing.T) {
	in := AppInput{Name: "PM", SCIMURL: "javascript:alert(1)"}
	if in.clean() == nil {
		t.Error("non-http SCIM URL accepted")
	}
	in = AppInput{Name: " PM ", Key: " PM-Tool ", SCIMURL: "https://pm.x.io/scim/v2/"}
	if err := in.clean(); err != nil || in.Key != "pm-tool" || in.SCIMURL != "https://pm.x.io/scim/v2" {
		t.Errorf("clean: %+v %v", in, err)
	}
}
