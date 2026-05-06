using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace CertificateValidation;

public class ValidationTests
{
    [Fact]
    public void ChainBuild_Should_BeTrue()
    {
        var rootCert = X509CertificateLoader.LoadCertificate(
            """
            -----BEGIN CERTIFICATE-----
            MIIC6jCCAdKgAwIBAgIIFyR3TsLCuLUwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UE
            AxMQUm9vdCBDZXJ0aWZpY2F0ZTAeFw0yNjAxMTIxMjA3MzJaFw0zNzExMzAxNDA3
            MzJaMBsxGTAXBgNVBAMTEFJvb3QgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEB
            AQUAA4IBDwAwggEKAoIBAQDQWW/Qelt6HgAErHoB5O/1jni+aYRus9W6lOc2C/so
            HMf/zkhWumFVyrLLT1f7s9TB+z1IvKH4c5nWbooguptT+lf0HN83no7acsBIvLFq
            LoWrZa2UTQEJcEfKWmw6ykIDJhbjZr7KiooNzKLeDPGCbiB4BXRcBmRHFdtM+vYn
            cRlKPd88ghquo5785TenEcQ6a9nnRTgROxtC8aZLrmUcpVFzOqVEN6pyP1anI0vk
            iXGlGSrqTEnQu7E0hSw/xYqmSnBw6Nrh8bN5rL7R8RinlaU17Gd/kd75xKFg3o7c
            dko4IeX0nk3KXXE43sX5DdYF6oVYsZ2z5aRLNAtIiGhDAgMBAAGjMjAwMA8GA1Ud
            EwEB/wQFMAMBAf8wHQYDVR0OBBYEFHi95pjPZ3H0H1Fl1ZXeXiIOwjfYMA0GCSqG
            SIb3DQEBCwUAA4IBAQCNqzOgCOWjdUXNV/dJ+xRkpvt3ZZtMN8f5a6SS7V6KH+4Z
            Fh7s26a2iH3h6mDZjtE3Cufxm6IU+rDvdQM/BPcPacEen9NqesYTl8mo9mFxr9j7
            81geyQ9gtgqkxLjmcOOkGoIrrlggKhm33hj2pB6m6dVxPe1Whl4/eEhe3PlKOUaq
            TsA8Xuh6C4b08E8ANamKm6YrtXSe6WeQB+da4lCeSN43+ZPFUvff8/dFoKUhMZKR
            nbVb4oHT91xUV9WXMoStqrhU7G0M6KA9rik+FNlDFhXIOyUYCYgl/H4Hjhy77nDE
            aQprJHQz/whPQn80s3KCJ2yJLl1Z/L2c8HFjAibu
            -----END CERTIFICATE-----
            """u8.ToArray());

        var brokenCert = X509CertificateLoader.LoadCertificate(
            """
            -----BEGIN CERTIFICATE-----
            MIIC6jCCAdKgAwIBAgIIFyR3TsLCuLUwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UE
            AxMQUm9vdCBDZXJ0aWZpY2F0ZTAeFw0yNjAxMTIxMjA3MzJaFw0zNzExMzAxNDA3
            MzJaMBsxGTAXBgNVBAMTEFJvb3QgQ2VydGlmaWNhdGUwggEiMA0GCSqGSIb3DQEB
            AQUAA4IBDwAwggEKAoIBAQDQWW/Qelt6HgAErHoB5O/1jni+aYRus9W6lOc2C/so
            HMf/zkhWumFVyrLLT1f7s9TB+z1IvKH4c5nWbooguptT+lf0HN83no7acsBIvLFq
            LoWrZa2UTQEJcEfKWmw6ykIDJhbjZr7KiooNzKLeDPGCbiB4BXRcBmRHFdtM+vYn
            cRlKPd88ghquo5785TenEcQ6a9nnRTgROxtC8aZLrmUcpVFzOqVEN6pyP1anI0vk
            iXGlGSrqTEnQu7E0hSw/xYqmSnBw6Nrh8bN5rL7R8RinlaU17Gd/kd75xKFg3o7c
            dko4IeX0nk3KXXE43sX5DdYF6oVYsZ2z5aRLNAtIiGhDAgMBAAGjMjAwMA8GA1Ud
            EwEB/wQFMAMBAf8wHQYDVR0OBBYEFHi95pjPZ3H0H1Fl1ZXeXiIOwjfYMA0GCSqG
            SIb3DQEBCwUAA4IBAQCNqzOgCOWjdUXNV/dJ+xRkpvt3ZZtMN8f5a6SS7V6KH+4Z
            Fh7s26a2iH3h6mDZjtE3Cufxm6IU+rDvdQM/BPcPacEen9NqesYTl8mo9mFxr9j7
            81geyQ9gtgqkxLjmcOOkGoIrrlggKhm33hj2pB6m6dVxPe1Whl4/eEhe3PlKOUaq
            TsA8Xuh6C4b08E8ANamKm6YrtXSe6WeQB+da4lCeSN43+ZPFUvff8/dFoKUhMZKR
            nbVb4oHT91xUV9WXMoStqrhU7G0M6KA9rik+FNlDFhXIOyUYCYgl/H4Hjhy77nDE
            aQprJHQz/whPQn80s3KCJ2yJLl1Z/AAAAAAAAaaa
            -----END CERTIFICATE-----
            """u8.ToArray());

        var interCert = X509CertificateLoader.LoadCertificate(
            """
            -----BEGIN CERTIFICATE-----
            MIIC1DCCAbygAwIBAgIJYXBwZW5kbWU6MA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV
            BAMTEFJvb3QgQ2VydGlmaWNhdGUwHhcNMjYwMTEyMTIwNzMzWhcNMzIxMTMwMTQw
            NzMzWjAjMSEwHwYDVQQDExhJbnRlcm1lZGlhdGUgQ2VydGlmaWNhdGUwggEiMA0G
            CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCjo75S5wRvFYts55fsQ/xk58m8a/A/
            w1DeT8pzdkZPDEGTH8SqVUlu3roADpnwBf8Q5qDnyNJKiOLwWrCVRxc6l9JGJ6Gt
            P5Wup9aICuCbTMdvDpnFEcQAaY6gohVeNHd1sMSSLLmRoOH/CJRa/Jqa3+b6JaNX
            uvEFLo3cCWKN/7hQIDbOBRSzNyairPFuqGqPlgQgkHY6hRMqr24IjJGx46o6Bxm2
            57kInE+93zmL3k40+IHWz+uO+vf1PghX1llWXhaQG8beVspLAVyt4idCKhToyFAz
            6yjqrtpol+hjy3oZJqvrKUd7ewFp3TIBP+QvKi03v1jB7YbslYgMK+snAgMBAAGj
            EzARMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIKxIP+WCHuy
            8Os74aKlFK1RTJf+NUL8MxEImT7+F3qYAILEpsNU+Bd0iNg0vbcIlsAHsAf8pfaO
            r5vV+2Pb2kwzhw1K0lANKMuUWornYR+Q/cPXJcll3T87rRighZvEt5Uv1uYtUtiL
            YabfYIUstMDPwsB8gNIlYfLDoNpQ/r0pS+QX8XzTXqf5oQ4A3Uj0xpFUNHQF9gCr
            4jtp66iCFuyRoPGjsxokvEmMhqYWy/4SYzfPguuFD+ko0C/wni8sI/FbrAW9WdJS
            rlgkBzdPt7Z60fDkfmzEaY8zuPxNTBEGMKNebv6ZiqyZvn1vPVRbhLHBGkg7QZUU
            NyhOimieJeE=
            -----END CERTIFICATE-----
            """u8.ToArray());

        var endpointCert = X509CertificateLoader.LoadCertificate(
            """
            -----BEGIN CERTIFICATE-----
            MIIC3TCCAcWgAwIBAgIJYXBwZW5kbWU6MA0GCSqGSIb3DQEBCwUAMCMxITAfBgNV
            BAMTGEludGVybWVkaWF0ZSBDZXJ0aWZpY2F0ZTAeFw0yNjA1MDUwOTQ1MjBaFw0y
            NzA1MDUxNDQ1MjBaMBQxEjAQBgNVBAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcN
            AQEBBQADggEPADCCAQoCggEBAIy/CWfnT2h1/UsabIP1OwgQBVV/U99hpE15ULf3
            B1Z3v/OFk3AbR7ojRTIpyN5uLgeMKiPL49n608ginQ9xvZa7VL81Z0BHFW+wHquU
            44i1Ds+mRAXt12z+zav62mbdvu/P7zRsKBkezyHNKscSoR7+PI6iFH+SY43iqRF9
            0ieWhs6ip5+g91oi+z1bu3SSILzdW8Iw0Ivj+4ISI7FFXJrw38mJAY4gNxnuBnzo
            10lAB0mFV1gZQc1U/AAngqqCBr7MaS6CrnjfLhHLYerUB1cafxlBx7TMBBFhEcBq
            1zfs+0IyIGAJOQW2i5PJ1rUpyrw+tRVoHw9ihjrbLuA98wUCAwEAAaMjMCEwCQYD
            VR0TBAIwADAUBgNVHREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggEB
            AHm7ajOHS1sbQULz0tf2IBgnWQWenAAJlFSTk8dID2hQZZ30Cdsd4UoLP29axFdx
            7AkcVVmmy9jd2LE82J4AYPgiKDKpKpyqS4ssJzJhLThrMoWaCidVgVQ8JDkkf4qf
            FzaWeJtZvXP5shpANlpx32FCN9YMwt0oZnWuAvA/SMPrVlgltLZgCjF1uGqFK3xQ
            gXEMe5fDqHyR6aqR9k088yGcSiIBxQF+B6VQhUJ81sQTqGITFjoKKhUkCnDzkQmw
            NnMGecAGxXNej2XErro5ZY66KsoCPBCt+jjXdYbGpLF/9DYjLOZUqCn6GKefxQuy
            eM2h9/EmzHcpL4qtG9JUonw=
            -----END CERTIFICATE-----
            """u8.ToArray());

        var chain = X509Chain.Create();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(rootCert);
        chain.ChainPolicy.ExtraStore.Add(interCert);
        chain.ChainPolicy.ExtraStore.Add(endpointCert);
        var buildResult = chain.Build(endpointCert);

        chain.ChainPolicy.CustomTrustStore.Clear();
        chain.ChainPolicy.CustomTrustStore.Add(brokenCert);

        var buildResultWithBrokenRoot = chain.Build(endpointCert);

        Assert.True(buildResult);
        Assert.False(buildResultWithBrokenRoot);
    }
}