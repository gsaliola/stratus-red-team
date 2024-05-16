package aws

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"

	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

var moduleNames []string = []string{
	"aws__enum_account",
	"cognito__enum",
	"ec2__enum",
	"iam__enum_users_roles_policies_groups",
	"lambda__enum",
}

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                 "aws.persistence.custom-reconnaissance",
		FriendlyName:       "Run reconnaissance scripts",
		Description:        ``,
		Detection:          ``,
		Platform:           stratus.AWS,
		IsIdempotent:       true,
		MitreAttackTactics: []mitreattack.Tactic{mitreattack.Discovery},
		Detonate:           detonate,
	})
}

func detonate(_ map[string]string, providers stratus.CloudProviders) error {
	app := "pacu"

	var args []string
	for _, module := range moduleNames {
		fmt.Println("[*] Running module: ", module)
		args = []string{
			"--session", "stratus",
			"--module-name", module,
			"--exec",
		}
		cmd := exec.Command(app, args...)

		cmd.Stdout = os.Stdout

		pipe, err := cmd.StdinPipe()

		if err != nil {
			return err
		}

		defer pipe.Close()

		pipe.Write([]byte("y\n"))

		if err = cmd.Start(); err != nil {
			return err
		}

		if err = cmd.Wait(); err != nil {
			return err
		}

	}

	return nil
}

// func getSessionName() string {
// 	return "session-" + RandomString(6)
// }

// func getKeys() string {
// 	return fmt.Sprintf("%s,%s,%s", keyAlias, aKey, pKey)
// }

// func RandomString(length int) string {
// 	const letterBytes = "abcdefghijklmnopqrstuvwxyz0123456789"
// 	b := make([]byte, length)
// 	for i := range b {
// 		b[i] = letterBytes[rand.Intn(len(letterBytes))]
// 	}
// 	return string(b)
// }
