package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	hOwn  = tpm2.TPMHandle(0x40000001)
	hEnd  = tpm2.TPMHandle(0x4000000B)
	hPlat = tpm2.TPMHandle(0x4000000C)
	hNull = tpm2.TPMHandle(0x40000007)
	hLck  = tpm2.TPMHandle(0x4000000A)

	p0 = tpm2.TPMHandle(0x00000000)
	pM = tpm2.TPMHandle(0x00000017)

	s0 = tpm2.TPMHandle(0x02000000)
	sM = tpm2.TPMHandle(0x02FFFFFF)

	t0 = tpm2.TPMHandle(0x80000000)
	tM = tpm2.TPMHandle(0x80FFFFFF)

	prm0 = tpm2.TPMHandle(0x81000000)
	prmM = tpm2.TPMHandle(0x81FFFFFF)

	srkRsa = tpm2.TPMHandle(0x81000001)
	srkEcc = tpm2.TPMHandle(0x81000002)
	ekRsa  = tpm2.TPMHandle(0x81010001)
	ekEcc  = tpm2.TPMHandle(0x81010002)
	akRsa  = tpm2.TPMHandle(0x81010003)
	akEcc  = tpm2.TPMHandle(0x81010004)
	devRsa = tpm2.TPMHandle(0x81020001)
	devEcc = tpm2.TPMHandle(0x81020002)
	vpnKey = tpm2.TPMHandle(0x81020005)

	nv0 = tpm2.TPMHandle(0x01000000)
	nvM = tpm2.TPMHandle(0x01FFFFFF)

	rsaCrt = tpm2.TPMHandle(0x01C00002)
	rsaNnc = tpm2.TPMHandle(0x01C00003)
	rsaTpl = tpm2.TPMHandle(0x01C00004)
	rsa3k  = tpm2.TPMHandle(0x01C00012)
	rsa4k  = tpm2.TPMHandle(0x01C00016)

	eccCrt = tpm2.TPMHandle(0x01C0000A)
	eccNnc = tpm2.TPMHandle(0x01C0000B)
	eccTpl = tpm2.TPMHandle(0x01C0000C)
	ecc384 = tpm2.TPMHandle(0x01C00014)

	rsaCrtA = tpm2.TPMHandle(0x01C00008)
	eccCrtA = tpm2.TPMHandle(0x01C0000F)

	pltCrt  = tpm2.TPMHandle(0x01C00004)
	pltCrtA = tpm2.TPMHandle(0x01C0000C)
	dPltCrt = tpm2.TPMHandle(0x01C00016)

	akRsaCrt = tpm2.TPMHandle(0x01C00005)
	akEccCrt = tpm2.TPMHandle(0x01C0000D)

	oem1 = tpm2.TPMHandle(0x01D00001)
	oem2 = tpm2.TPMHandle(0x01D00002)
	wBl  = tpm2.TPMHandle(0x01100001)
	wHel = tpm2.TPMHandle(0x01100002)
	lIma = tpm2.TPMHandle(0x01200001)

	swVer = tpm2.TPMHandle(0x01000001)
	secBt = tpm2.TPMHandle(0x01000002)
)

var (
	oSec []byte
	eSec []byte
	lSec []byte
)

func hasNv(t transport.TPM, h tpm2.TPMHandle) bool {
	_, err := tpm2.NVReadPublic{NVIndex: h}.Execute(t)
	return err == nil
}

func hasKey(t transport.TPM, h tpm2.TPMHandle) bool {
	_, err := tpm2.ReadPublic{ObjectHandle: h}.Execute(t)
	return err == nil
}

func rmKey(t transport.TPM, h tpm2.TPMHandle) error {
	if hasKey(t, h) {
		r, err := tpm2.ReadPublic{ObjectHandle: h}.Execute(t)
		if err != nil {
			return err
		}
		_, err = tpm2.EvictControl{
			Auth: tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Auth:   tpm2.PasswordAuth(oSec),
			},
			ObjectHandle: tpm2.AuthHandle{
				Handle: h,
				Name:   r.Name,
				Auth:   tpm2.PasswordAuth(nil),
			},
			PersistentHandle: h,
		}.Execute(t)
		if err != nil {
			return err
		}
	}
	return nil
}

func mkKey(t transport.TPM, hHier tpm2.TPMHandle, sec []byte, tpl tpm2.TPMTPublic, hPerm tpm2.TPMHandle) (crypto.PublicKey, error) {
	if err := rmKey(t, hPerm); err != nil {
		return nil, err
	}
	c, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: hHier,
			Auth:   tpm2.PasswordAuth(sec),
		},
		InPublic: tpm2.New2B(tpl),
	}.Execute(t)
	if err != nil {
		return nil, err
	}
	defer func() {
		tpm2.FlushContext{FlushHandle: c.ObjectHandle}.Execute(t)
	}()
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(oSec),
		},
		ObjectHandle: tpm2.AuthHandle{
			Handle: c.ObjectHandle,
			Name:   c.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PersistentHandle: hPerm,
	}.Execute(t)
	if err != nil {
		return nil, err
	}
	pub, err := c.OutPublic.Contents()
	if err != nil {
		return nil, err
	}
	cPub, err := tpm2.Pub(*pub)
	if err != nil {
		return nil, err
	}
	return cPub, nil
}

func mkCrt(pub crypto.PublicKey, cn string, mkr string) ([]byte, error) {
	cCN := "Intel TPM EK Intermediate CA"
	cO := "Intel Corporation"
	cOU := "Intel TPM Identity Authority"
	cC := "US"
	eO := "Intel Corporation"
	eOU := "Intel TPM"

	switch strings.ToLower(mkr) {
	case "amd":
		cCN = "AMD TPM EK Intermediate CA"
		cO = "Advanced Micro Devices"
		cOU = "AMD TPM Certification Authority"
		cC = "US"
		eO = "Advanced Micro Devices"
		eOU = "AMD Hardware TPM"
	case "infineon":
		cCN = "Infineon TPM EK Intermediate CA"
		cO = "Infineon Technologies AG"
		cOU = "Infineon TPM Root CA"
		cC = "DE"
		eO = "Infineon Technologies AG"
		eOU = "OPTIGA(TM) TPM"
	case "nuvoton":
		cCN = "Nuvoton TPM EK Intermediate CA"
		cO = "Nuvoton Technology Corporation"
		cOU = "Nuvoton TPM Identity CA"
		cC = "TW"
		eO = "Nuvoton Technology Corporation"
		eOU = "Nuvoton Safety chip"
	case "stmicro":
		cCN = "STMicroelectronics TPM EK Intermediate CA"
		cO = "STMicroelectronics"
		cOU = "STMicroelectronics TPM CA"
		cC = "FR"
		eO = "STMicroelectronics"
		eOU = "STSafe TPM"
	case "microsoft":
		cCN = "Microsoft TPM EK Intermediate CA"
		cO = "Microsoft Corporation"
		cOU = "Microsoft TPM Root CA"
		cC = "US"
		eO = "Microsoft Corporation"
		eOU = "Microsoft Windows fTPM"
	case "generic":
		cCN = "Elliot TPM Root CA"
		cO = "Elliot TPM Enterprise CA"
		cOU = "Elliot Provisioning Authority"
		cC = "US"
		eO = "Elliot TPM Enterprise CA"
		eOU = "Elliot TPM"
	}

	cPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	lim := new(big.Int).Lsh(big.NewInt(1), 128)
	cSer, err := rand.Int(rand.Reader, lim)
	if err != nil {
		return nil, err
	}
	cTpl := x509.Certificate{
		SerialNumber: cSer,
		Subject: pkix.Name{
			Country:            []string{cC},
			Organization:       []string{cO},
			OrganizationalUnit: []string{cOU},
			Locality:           []string{"Silicon Valley"},
			CommonName:         cCN,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(15, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	cDer, err := x509.CreateCertificate(rand.Reader, &cTpl, &cTpl, &cPriv.PublicKey, cPriv)
	if err != nil {
		return nil, err
	}
	cCert, err := x509.ParseCertificate(cDer)
	if err != nil {
		return nil, err
	}
	certSer, err := rand.Int(rand.Reader, lim)
	if err != nil {
		return nil, err
	}
	eTpl := x509.Certificate{
		SerialNumber: certSer,
		Subject: pkix.Name{
			Country:            []string{cC},
			Organization:       []string{eO},
			OrganizationalUnit: []string{eOU},
			CommonName:         cn,
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().AddDate(8, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}
	eDer, err := x509.CreateCertificate(rand.Reader, &eTpl, cCert, pub, cPriv)
	if err != nil {
		return nil, err
	}
	return eDer, nil
}

func wrNv(t transport.TPM, h tpm2.TPMHandle, hAlt tpm2.TPMHandle, data []byte) {
	if hasNv(t, h) {
		_, err := tpm2.NVUndefineSpace{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(oSec)},
			NVIndex:    tpm2.NamedHandle{Handle: h},
		}.Execute(t)
		if err != nil {
			h = hAlt
			if hasNv(t, h) {
				tpm2.NVUndefineSpace{
					AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(oSec)},
					NVIndex:    tpm2.NamedHandle{Handle: h},
				}.Execute(t)
			}
		}
	}
	pub := tpm2.TPMSNVPublic{
		NVIndex: h,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true,
			OwnerRead:  true,
			AuthRead:   true,
			NoDA:       true,
		},
		DataSize: uint16(len(data)),
	}
	_, _ = tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(oSec)},
		Auth:       tpm2.TPM2BAuth{},
		PublicInfo: tpm2.New2B(pub),
	}.Execute(t)

	cs := 512
	p := 0
	for p < len(data) {
		e := p + cs
		if e > len(data) {
			e = len(data)
		}
		chk := data[p:e]
		rPub, err := tpm2.NVReadPublic{NVIndex: h}.Execute(t)
		if err != nil {
			return
		}
		_, err = tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(oSec)},
			NVIndex:    tpm2.NamedHandle{Handle: h, Name: rPub.NVName},
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: chk},
			Offset:     uint16(p),
		}.Execute(t)
		if err != nil {
			return
		}
		p = e
	}
}

func updSec(t transport.TPM) {
	if len(oSec) > 0 {
		_, _ = tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			NewAuth:    tpm2.TPM2BAuth{Buffer: oSec},
		}.Execute(t)
	}
	if len(eSec) > 0 {
		_, _ = tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHEndorsement, Auth: tpm2.PasswordAuth(nil)},
			NewAuth:    tpm2.TPM2BAuth{Buffer: eSec},
		}.Execute(t)
	}
	if len(lSec) > 0 {
		_, _ = tpm2.HierarchyChangeAuth{
			AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHLockout, Auth: tpm2.PasswordAuth(nil)},
			NewAuth:    tpm2.TPM2BAuth{Buffer: lSec},
		}.Execute(t)
	}
}

func rmCerts(t transport.TPM) error {
	hs := []tpm2.TPMHandle{
		rsaCrt, rsaNnc, rsaTpl, rsa3k, rsa4k, eccCrt, eccNnc, eccTpl, ecc384,
		pltCrt, pltCrtA, dPltCrt, akRsaCrt, akEccCrt,
		oem1, oem2, wBl, wHel, lIma, swVer, secBt,
	}
	for _, h := range hs {
		if hasNv(t, h) {
			_, _ = tpm2.NVUndefineSpace{
				AuthHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(oSec)},
				NVIndex:    tpm2.NamedHandle{Handle: h},
			}.Execute(t)
		}
	}
	return nil
}

func rmKeys(t transport.TPM) error {
	hs := []tpm2.TPMHandle{ekRsa, ekEcc, srkRsa, srkEcc, akRsa, akEcc}
	for _, h := range hs {
		_ = rmKey(t, h)
	}
	return nil
}

func extPcr(t transport.TPM, data []byte) error {
	ps := []uint32{0, 1, 2, 3, 4, 5, 6, 7, 11, 14}
	algs := []tpm2.TPMAlgID{tpm2.TPMAlgSHA1, tpm2.TPMAlgSHA256}
	for _, p := range ps {
		for _, alg := range algs {
			var d []byte
			if alg == tpm2.TPMAlgSHA1 {
				d = data[:20]
			} else {
				d = data
			}
			_, _ = tpm2.PCRExtend{
				PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(p), Auth: tpm2.PasswordAuth(nil)},
				Digests: tpm2.TPMLDigestValues{
					Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMIAlgHash(alg), Digest: d}},
				},
			}.Execute(t)
		}
	}
	return nil
}

func doAll(t transport.TPM, data []byte, mkr string) (crypto.PublicKey, crypto.PublicKey, error) {
	oRsa := tpm2.RSAEKTemplate
	oEcc := tpm2.ECCEKTemplate
	oSRsa := tpm2.RSASRKTemplate
	oSEcc := tpm2.ECCSRKTemplate

	if len(data) > 0 {
		oRsa.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: data})
		oEcc.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: data},
			Y: tpm2.TPM2BECCParameter{Buffer: data},
		})
		oSRsa.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: data})
		oSEcc.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: data},
			Y: tpm2.TPM2BECCParameter{Buffer: data},
		})
	}

	pRsa, err := mkKey(t, tpm2.TPMRHEndorsement, eSec, oRsa, ekRsa)
	if err != nil {
		return nil, nil, err
	}
	pEcc, err := mkKey(t, tpm2.TPMRHEndorsement, eSec, oEcc, ekEcc)
	if err != nil {
		return nil, nil, err
	}
	_, err = mkKey(t, tpm2.TPMRHOwner, oSec, oSRsa, srkRsa)
	if err != nil {
		return nil, nil, err
	}
	_, err = mkKey(t, tpm2.TPMRHOwner, oSec, oSEcc, srkEcc)
	if err != nil {
		return nil, nil, err
	}

	akRTpl := tpm2.RSAEKTemplate
	akRTpl.ObjectAttributes.Decrypt = false
	akRTpl.ObjectAttributes.SignEncrypt = true
	akRTpl.ObjectAttributes.Restricted = true
	if len(data) > 0 {
		akRTpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: data})
	}
	akRTpl.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
		Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
		Scheme: tpm2.TPMTRSAScheme{
			Scheme:  tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgRSASSA, &tpm2.TPMSSigSchemeRSASSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		KeyBits: 2048,
	})
	_, err = mkKey(t, tpm2.TPMRHOwner, oSec, akRTpl, akRsa)
	if err != nil {
		return nil, nil, err
	}

	akETpl := tpm2.ECCEKTemplate
	akETpl.ObjectAttributes.Decrypt = false
	akETpl.ObjectAttributes.SignEncrypt = true
	akETpl.ObjectAttributes.Restricted = true
	if len(data) > 0 {
		akETpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: data},
			Y: tpm2.TPM2BECCParameter{Buffer: data},
		})
	}
	akETpl.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
		Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
		Scheme: tpm2.TPMTECCScheme{
			Scheme:  tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUAsymScheme(tpm2.TPMAlgECDSA, &tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256}),
		},
		CurveID: tpm2.TPMECCNistP256,
	})
	_, err = mkKey(t, tpm2.TPMRHOwner, oSec, akETpl, akEcc)
	if err != nil {
		return nil, nil, err
	}

	if pRsa != nil {
		cDer, err := mkCrt(pRsa, "RSA-2048 Endorsement Identity", mkr)
		if err == nil {
			wrNv(t, rsaCrt, rsaCrtA, cDer)
		}
	}
	if pEcc != nil {
		cDer, err := mkCrt(pEcc, "ECC P256 Endorsement Identity", mkr)
		if err == nil {
			wrNv(t, eccCrt, eccCrtA, cDer)
		}
	}
	if pRsa != nil {
		cDer, err := mkCrt(pRsa, "OEM Platform Identity Credential", mkr)
		if err == nil {
			wrNv(t, pltCrt, pltCrtA, cDer)
		}
	}
	return pRsa, pEcc, nil
}

func brkLck(t transport.TPM) error {
	return nil
}

func main() {
	d := make([]byte, 32)
	if _, err := rand.Read(d); err != nil {
		os.Exit(1)
	}

	mkrs := []string{"intel", "amd", "infineon", "nuvoton", "stmicro", "microsoft"}
	var s [1]byte
	if _, err := rand.Read(s[:]); err != nil {
		os.Exit(1)
	}
	mkr := mkrs[int(s[0])%len(mkrs)]

	t, err := transport.OpenTPM()
	if err != nil {
		os.Exit(1)
	}
	defer t.Close()

	updSec(t)
	_ = brkLck(t)
	_ = rmCerts(t)
	_ = rmKeys(t)
	_, _, err = doAll(t, d, mkr)
	if err != nil {
		os.Exit(1)
	}
	_ = extPcr(t, d)
	os.Exit(0)
}
