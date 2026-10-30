package services

import (
    "github.com/pquerna/otp"
    "github.com/pquerna/otp/totp"
)

func GenerateTOTP(email string) (*otp.Key, error) {
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      "SecurityBank",
        AccountName: email,
        Period:      30,
        Digits:      otp.DigitsSix,
        Algorithm:   otp.AlgorithmSHA1,
    })

    if err != nil {
        return nil, err
    }

    return key, nil
}

func VerifyTOTP(secret string, code string) bool {
    return totp.Validate(code, secret)
}