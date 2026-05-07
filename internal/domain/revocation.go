package domain

import "time"

// AgentRevocation records the metadata of an agent revocation event.
type AgentRevocation struct {
	RegistrationID              int64               `json:"registrationId"`
	AnsName                     AnsName             `json:"ansName"`
	AgentID                     string              `json:"agentId"`
	PreviousStatus              RegistrationStatus  `json:"previousStatus"`
	RevokedAt                   time.Time           `json:"revokedAt"`
	Reason                      RevocationReason    `json:"reason"`
	Comments                    string              `json:"comments,omitempty"`
	RevokedIdentityCertificates []StoredCertificate `json:"revokedIdentityCertificates,omitempty"`
	RevokedServerCertificates   []StoredCertificate `json:"revokedServerCertificates,omitempty"`
}
