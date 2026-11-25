package fixtures

import "encoding/json"

type brokerMessage struct {
	ClientID string
	TenantID string
}

type writer interface {
	Write(v any) error
}

type verifier interface {
	Verify(b []byte) error
}

func handlePayload(payload []byte) error {
	var m brokerMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return err
	}
	_ = m.ClientID // ruleid: sgate-go-message-identity-without-signature
	return nil
}

func handleVerified(payload []byte, v verifier) error {
	var m brokerMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		return err
	}
	if err := v.Verify(payload); err != nil {
		return err
	}
	_ = m.ClientID // ok: sgate-go-message-identity-without-signature
	return nil
}

func handleWrite(w writer, v any) error {
	if err := w.Write(v); err != nil { // ruleid: sgate-go-broker-write-error-retry
		return err
	}
	return nil
}
