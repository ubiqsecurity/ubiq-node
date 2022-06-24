const ubiq = require('../index');

async function testFpe({
    options, tweakFF1 = [], ubiqCredentials = null, cipherText = null, checkResult = true,
}) {
    if (!ubiqCredentials) {
        ubiqCredentials = new ubiq.ConfigCredentials('./credentials');
    }
    const ubiqEncryptDecrypt = new ubiq.fpeEncryptDecrypt.FpeEncryptDecrypt({ ubiqCredentials });
    if (!cipherText) {
        cipherText = await ubiqEncryptDecrypt.EncryptAsync(
            options.FfsName,
            options.EncryptText,
            tweakFF1,
        );
    }
    const plainText = await ubiqEncryptDecrypt.DecryptAsync(
        options.FfsName,
        cipherText,
        tweakFF1,
    );
    if (checkResult) {
        expect(plainText).toBe(options.EncryptText);
    }
    return { cipherText, plainText };
}
test('EncryptFPE_FFS_ALPHANUM_SSN_Success', async () => {
    const tweakFF1 = [];

    const options = {
        FfsName: 'ALPHANUM_SSN',
        EncryptText: '123-45-6789',
    };
    await testFpe({ tweakFF1, options });
});
test(
    'EncryptFPE_FFS_ALPHANUM_SSN_ValidPassthroughCharacters_Success',
    async () => {
        const tweakFF1 = [];
        const options = {
            FfsName: 'ALPHANUM_SSN',
            EncryptText: ' 01&23-456-78-90',
        };
        await testFpe({ tweakFF1, options });
    },
    30000,
);

test('EncryptFPE_SIMPLE_FFS_ALPHANUM_SSN_Success', async () => {
    const tweakFF1 = [];

    const options = {
        FfsName: 'ALPHANUM_SSN',
        EncryptText: ' 123-45-6789',
    };

    const cipherText1 = await testFpe({ options, tweakFF1 });
    const cipherText2 = await testFpe({ options, tweakFF1 });

    expect(cipherText1.cipherText).toBe(cipherText2.cipherText);
    expect(cipherText1.plainText).toBe(cipherText2.plainText);
});

test('EncryptFPE_FFS_ALPHANUM_SSN_InValidPassthroughCharacters_Fail', async () => {
    const tweakFF1 = [];

    const ffsName = 'ALPHANUM_SSN';
    const original = '1$23-45-6789';

    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('invalid character found in the input:$');
});
test('EncryptFPE_FFS_BIRTH_DATE_Success', async () => {
    // TODO: Figure out how to handle credentials
    // const credentials = UbiqFactory.ReadCredentialsFromFile('..\\..\\credentials', 'default');

    const tweakFF1 = [];
    const ffsName = 'BIRTH_DATE';
    const original = '01-01-2020';
    await testFpe({ options: { FfsName: ffsName, EncryptText: original, tweakFF1 } });
});
test('EncryptFPE_FFS_BIRTH_DATE_InValidPassthroughCharacters_Fail', async () => {
    const tweakFF1 = [];

    const ffsName = 'BIRTH_DATE';
    const original = '01/01/2020';

    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('invalid character found in the input:/');
});

test('EncryptFPE_FFS_SO_ALPHANUM_PIN_Success', async () => {
    // TODO: Figure out how to handle credentials
    const tweakFF1 = [];

    const ffsName = 'SO_ALPHANUM_PIN';
    const original = 'ABCD';

    await testFpe({
        options:
            { FfsName: ffsName, EncryptText: original, tweakFF1 },
    });
});

test('EncryptFPE_FFS_SO_ALPHANUM_PIN_ALL_NUMBERS__Success', async () => {
    // TODO: Figure out how to handle credentials

    const tweakFF1 = [];

    const ffsName = 'SO_ALPHANUM_PIN';
    const original = '1234';

    await testFpe({
        options:
            { FfsName: ffsName, EncryptText: original, tweakFF1 },
    });
});
test('EncryptFPE_FFS_SO_ALPHANUM_PIN_ValidPassthroughCharacters_Success', async () => {
    // TODO: Figure out how to handle credentials

    const tweakFF1 = [];
    const ffsName = 'SO_ALPHANUM_PIN';
    const original = 'AB^CD';

    await testFpe({
        options:
            { FfsName: ffsName, EncryptText: original, tweakFF1 },
    });
});
test('EncryptFPE_XPlatformValidation_Success', async () => {
    // TODO: Figure out how to handle credentials

    const tweakFF1 = [];
    const ffsName = 'ALPHANUM_SSN';
    const original = '123 456 789';

    await testFpe({
        options:
            { FfsName: ffsName, EncryptText: original, tweakFF1 },
    });
});

test('EncryptFPE_XPlatformValidation_Success', async () => {
    const tweakFF1 = [];

    const ffsName = 'ALPHANUM_SSN';
    const original = '123 456 789';

    await testFpe({
        options:
            { FfsName: ffsName, EncryptText: original, tweakFF1 },
    });
});

test('EncryptFPE_FFS_SO_ALPHANUM_PIN_InValidPassthroughCharacters_Fail', async () => {
    const tweakFF1 = [];

    const ffsName = 'SO_ALPHANUM_PIN';
    const original = 'AB+CD';

    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('invalid character found in the input:+');
});

test('EncryptFPE_FFS_GENERIC_STRING_Success', async () => {
    const tweakFF1 = [
        0x39, 0x38, 0x37, 0x36,
        0x35, 0x34, 0x33, 0x32,
        0x31, 0x30, 0x33, 0x32,
        0x31, 0x30, 0x32,
    ];

    const ffsName = 'GENERIC_STRING';
    const original = 'A STRING OF AT LEAST 15 UPPER CHARACTERS';
    await testFpe({
        options:
            { FfsName: ffsName, EncryptText: original, tweakFF1 },
    });
});

test('EncryptFPE_InvalidFFS', async () => {
    const tweakFF1 = [];

    const ffsName = 'ERROR FFS';
    const original = 'ABCDEFGHI';
    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('Invalid FFS name');
});

test('EncryptFPE_InvalidCredentials', async () => {
    const ubiqCredentials = new ubiq.Credentials('a', 'b', 'c', 'dev-cluster.koala.ubiqsecurity.com');
    const tweakFF1 = [];
    const ffsName = 'ALPHANUM_SSN';
    const original = 'ABCDEFGHI';
    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
        ubiqCredentials,
    })).rejects.toThrowError('Unauthorized Request');
});

test('EncryptFPE_Invalid_PT_CT', async () => {
    const tweakFF1 = [];

    const ffsName = 'SSN';
    const original = ' 123456789$';

    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('invalid character found in the input:$');
});

test('EncryptFPE_Invalid_LEN_1', async () => {
    const tweakFF1 = [];

    const ffsName = 'SSN';
    const original = ' 1234';

    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('Invalid input len min: 9 max: 9');
});

test('EncryptFPE_Invalid_LEN_2', async () => {
    const tweakFF1 = [];
    const ffsName = 'SSN';
    const original = ' 12345678901234567890';
    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('Invalid input len min: 9 max: 9');
});

test('EncryptFPE_Invalid_specific_creds_1', async () => {
    const ubiqCredentialsFile = new ubiq.ConfigCredentials('./credentials');
    const ubiqCredentials = new ubiq.Credentials(
        ubiqCredentialsFile.access_key_id.substring(0, 1),
        ubiqCredentialsFile.secret_signing_key,
        ubiqCredentialsFile.secret_crypto_access_key,
        ubiqCredentialsFile.host,
    );
    const tweakFF1 = [];
    const ffsName = 'ALPHANUM_SSN';
    const original = ' 123456789';
    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
        ubiqCredentials,
    })).rejects.toThrowError('Unauthorized Request');
});

test('EncryptFPE_Invalid_specific_creds_2', async () => {
    const ubiqCredentialsFile = new ubiq.ConfigCredentials('./credentials');
    const ubiqCredentials = new ubiq.Credentials(
        ubiqCredentialsFile.access_key_id,
        ubiqCredentialsFile.secret_signing_key.substring(0, 1),
        ubiqCredentialsFile.secret_crypto_access_key,
        ubiqCredentialsFile.host,
    );
    const tweakFF1 = [];
    const ffsName = 'ALPHANUM_SSN';
    const original = ' 123456789';
    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
        ubiqCredentials,
    })).rejects.toThrowError('Unauthorized Request');
});

test('EncryptFPE_Invalid_specific_creds_3', async () => {
    const ubiqCredentialsFile = new ubiq.ConfigCredentials('./credentials');
    const ubiqCredentials = new ubiq.Credentials(
        ubiqCredentialsFile.access_key_id,
        ubiqCredentialsFile.secret_signing_key,
        ubiqCredentialsFile.secret_crypto_access_key.substring(0, 1),
        ubiqCredentialsFile.host,
    );
    const tweakFF1 = [];
    const ffsName = 'ALPHANUM_SSN';
    const original = ' 123456789';
    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
        ubiqCredentials,
    })).rejects.toThrowError('Problem decrypting ENCRYPTED private key');
});

test('EncryptFPE_Invalid_specific_creds_4', async () => {
    const ubiqCredentialsFile = new ubiq.ConfigCredentials('./credentials');
    const ubiqCredentials = new ubiq.Credentials(
        ubiqCredentialsFile.access_key_id,
        ubiqCredentialsFile.secret_signing_key,
        ubiqCredentialsFile.secret_crypto_access_key,
        'pi.ubiqsecurity.com',
    );
    const tweakFF1 = [];
    const ffsName = 'ALPHANUM_SSN';
    const original = ' 123456789';
    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
        ubiqCredentials,
    })).rejects.toThrowError('URL not found.');
});

test('EncryptFPE_Invalid_specific_creds_5', async () => {
    const ubiqCredentialsFile = new ubiq.ConfigCredentials('./credentials');
    const ubiqCredentials = new ubiq.Credentials(
        ubiqCredentialsFile.access_key_id,
        ubiqCredentialsFile.secret_signing_key,
        ubiqCredentialsFile.secret_crypto_access_key,
        'ps.ubiqsecurity.com',
    );
    const tweakFF1 = [];
    const ffsName = 'ALPHANUM_SSN';
    const original = ' 123456789';
    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        ubiqCredentials,
        checkResult: false,
    })).rejects.toThrowError('URL not found.');
});

test('EncryptFPE_Invalid_specific_creds_6', async () => {
    const ubiqCredentialsFile = new ubiq.ConfigCredentials('./credentials');
    const ubiqCredentials = new ubiq.Credentials(
        ubiqCredentialsFile.access_key_id,
        ubiqCredentialsFile.secret_signing_key,
        ubiqCredentialsFile.secret_crypto_access_key,
        'https://google.com',
    );

    const tweakFF1 = [];
    const ffsName = 'ALPHANUM_SSN';
    const original = ' 123456789';

    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        ubiqCredentials,
        checkResult: false,
    })).rejects.toThrowError('Could not load FfsName: ALPHANUM_SSN');
});

test('EncryptFPE_Invalid_keynum', async () => {
    const tweakFF1 = [];

    const ffsName = 'SO_ALPHANUM_PIN';
    const original = ' 0123';
    const { cipherText } = await testFpe({
        options:
            { FfsName: ffsName, EncryptText: original, tweakFF1 },
    });
    const arr = cipherText.split('');
    arr[0] = '}';
    const newcipher = arr.join('');

    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: newcipher,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('invalid character found in the input:}');
});

test('EncryptFPE_Error_handling_invalid_ffs', async () => {
    const tweakFF1 = [];

    const ffsName = 'ERROR_MSG';
    const original = ' 01121231231231231& 1 &2311200 ';

    await expect(testFpe({
        options: {
            FfsName: ffsName,
            EncryptText: original,
            tweakFF1,
        },
        checkResult: false,
    })).rejects.toThrowError('Invalid FFS name');
});
