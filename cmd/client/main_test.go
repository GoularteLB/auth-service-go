package main

import (
	"strings"
	"testing"
)

func TestSplitCreateArgs(t *testing.T) {
	scopes, audiences, err := splitCreateArgs([]string{"session:exchange", "--audience", "pedidos,estoque", "x:y", "--audience", "pagamentos"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(scopes, " ") != "session:exchange x:y" {
		t.Errorf("escopos = %v", scopes)
	}
	if strings.Join(audiences, " ") != "pedidos estoque pagamentos" {
		t.Errorf("audiências = %v", audiences)
	}

	if _, _, err := splitCreateArgs([]string{"x:y", "--audience"}); err == nil {
		t.Error("aceitou --audience sem valor")
	}
	scopes, audiences, err = splitCreateArgs(nil)
	if err != nil || len(scopes) != 0 || len(audiences) != 0 {
		t.Errorf("sem argumentos: %v %v %v", scopes, audiences, err)
	}
}
