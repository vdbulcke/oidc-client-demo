package pkce

import "testing"

func TestCodeVerifierLength(t *testing.T) {

	// test min length
	_, err := NewCodeVerifier(2)
	if err == nil {

		t.Log(err)
		t.Fail()
	}

	_, err = NewCodeVerifier(150)
	if err == nil {

		t.Log(err)
		t.Fail()
	}

}

func TestNewCodeVerifierCharset(t *testing.T) {

	code, err := NewCodeVerifier(45)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	for _, c := range code {

		// validated each generated character are in the
		// charset
		if !include(c, charSet) {
			t.Log(c)
			t.Fail()
		}
	}

}

func include(c rune, list string) bool {

	for _, v := range list {

		if v == c {
			return true
		}
	}
	return false
}

func TestNewChallenge(t *testing.T) {

	// gen new random code
	code, err := NewCodeVerifier(50)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	_, err = NewCodeChallenge(code, PKCEMethodS256)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	testCode := "ZpJiIM_G0SE9WlxzS69Cq0mQh8uyFaeEbILlW8tHs62SmEE6n7Nke0XJGx_F4OduTI4"

	testChallenge, err := NewCodeChallenge(testCode, PKCEMethodS256)
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	if testChallenge != "j3wKnK2Fa_mc2tgdqa6GtUfCYjdWSA5S23JKTTtPF8Y" {
		t.Log("challenge", testChallenge)
		t.Fail()
	}

}
