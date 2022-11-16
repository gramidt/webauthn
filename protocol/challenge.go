package protocol

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

// ChallengeLength - Length of bytes to generate for a challenge
const ChallengeLength = 32

// Challenge that should be signed and returned by the authenticator
type Challenge URLEncodedBase64

// Create a new challenge to be sent to the authenticator. The spec recommends using
// at least 16 bytes with 100 bits of entropy. We use 32 bytes.
func CreateChallenge() (Challenge, error) {
	challenge := make([]byte, ChallengeLength)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	return challenge, nil
}

func (c Challenge) String() string {
	return base64.RawURLEncoding.EncodeToString(c)
}

func (c Challenge) MarshalJSON() ([]byte, error) {
	return URLEncodedBase64(c).MarshalJSON()
}

func (c *Challenge) UnmarshalJSON(data []byte) error {
	var encoded URLEncodedBase64

	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}

	*c = Challenge(encoded)

	return nil
}
