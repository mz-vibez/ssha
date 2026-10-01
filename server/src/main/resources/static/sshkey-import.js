// Reads an existing private key on the phone, so it can be stored like a generated one (see ssh.js).
// Runs in the browser because the private key must never reach the server.
//
// Supports Ed25519 and RSA keys as OpenSSH private key files (with or without passphrase, as written
// by ssh-keygen), RSA as PKCS#1 PEM, and both as unencrypted PKCS#8 PEM (openssl). OpenSSH protects
// passphrases with bcrypt-pbkdf, which WebCrypto lacks, so it is implemented below on top of Blowfish.
(function () {
    // --- Blowfish / bcrypt-pbkdf (OpenBSD bcrypt_pbkdf.c) -----------------------------------------

    // Blowfish's initial P-array and S-boxes: the first 8336 hexadecimal digits of pi's fraction.
    const PI_HEX = `
        243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d01377be5466cf34e90c6c
        c0ac29b7c97c50dd3f84d5b5b54709179216d5d98979fb1bd1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96
        ba7c9045f12c7f9924a19947b3916cf70801f2e2858efc16636920d871574e69a458fea3f4933d7e0d95748f728eb658
        718bcd5882154aee7b54a41dc25a59b59c30d5392af26013c5d1b023286085f0ca417918b8db38ef8e79dcb0603a180e
        6c9e0e8bb01e8a3ed71577c1bd314b2778af2fda55605c60e65525f3aa55ab945748986263e8144055ca396a2aab10b6
        b4cc5c341141e8cea15486af7c72e993b3ee1411636fbc2a2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c
        7a325381289586773b8f48986b4bb9afc4bfe81b6628219361d809ccfb21a991487cac605dec8032ef845d5de98575b1
        dc262302eb651b8823893e81d396acc50f6d6ff383f442392e0b4482a484200469c8f04a9e1f9b5e21c66842f6e96c9a
        670c9c61abd388f06a51a0d2d8542f68960fa728ab5133a36eef0b6c137a3be4ba3bf0507efb2a98a1f1651d39af0176
        66ca593e82430e888cee8619456f9fb47d84a5c33b8b5ebee06f75d885c12073401a449f56c16aa64ed3aa62363f7706
        1bfedf72429b023d37d0d724d00a1248db0fead349f1c09b075372c980991b7b25d479d8f6e8def7e3fe501ab6794c3b
        976ce0bd04c006bac1a94fb6409f60c45e5c9ec2196a246368fb6faf3e6c53b51339b2eb3b52ec6f6dfc511f9b30952c
        cc814544af5ebd09bee3d004de334afd660f2807192e4bb3c0cba85745c8740fd20b5f39b9d3fbdb5579c0bd1a60320a
        d6a100c6402c7279679f25fefb1fa3cc8ea5e9f8db3222f83c7516dffd616b152f501ec8ad0552ab323db5fafd238760
        53317b483e00df829e5c57bbca6f8ca01a87562edf1769dbd542a8f6287effc3ac6732c68c4f5573695b27b0bbca58c8
        e1ffa35db8f011a010fa3d98fd2183b84afcb56c2dd1d35b9a53e479b6f84565d28e49bc4bfb9790e1ddf2daa4cb7e33
        62fb1341cee4c6e8ef20cada36774c01d07e9efe2bf11fb495dbda4dae909198eaad8e716b93d5a0d08ed1d0afc725e0
        8e3c5b2f8e7594b78ff6e2fbf2122b648888b812900df01c4fad5ea0688fc31cd1cff191b3a8c1ad2f2f2218be0e1777
        ea752dfe8b021fa1e5a0cc0fb56f74e818acf3d6ce89e299b4a84fe0fd13e0b77cc43b81d2ada8d9165fa26680957705
        93cc7314211a1477e6ad206577b5fa86c75442f5fb9d35cfebcdaf0c7b3e89a0d6411bd3ae1e7e4900250e2d2071b35e
        226800bb57b8e0af2464369bf009b91e5563911d59dfa6aa78c14389d95a537f207d5ba202e5b9c5832603766295cfa9
        11c819684e734a41b3472dca7b14a94a1b5100529a532915d60f573fbc9bc6e42b60a47681e6740008ba6fb5571be91f
        f296ec6b2a0dd915b6636521e7b9f9b6ff34052ec585566453b02d5da99f8fa108ba47996e85076a4b7a70e9b5b32944
        db75092ec4192623ad6ea6b049a7df7d9cee60b88fedb266ecaa8c71699a17ff5664526cc2b19ee1193602a575094c29
        a0591340e4183a3e3f54989a5b429d656b8fe4d699f73fd6a1d29c07efe830f54d2d38e6f0255dc14cdd20868470eb26
        6382e9c6021ecc5e09686b3f3ebaefc93c9718146b6a70a1687f358452a0e286b79c5305aa5007373e07841c7fdeae5c
        8e7d44ec5716f2b8b03ada37f0500c0df01c1f040200b3ffae0cf51a3cb574b225837a58dc0921bdd19113f97ca92ff6
        9432477322f547013ae5e58137c2dadcc8b576349af3dda7a94461460fd0030eecc8c73ea4751e41e238cd993bea0e2f
        3280bba1183eb3314e548b384f6db9086f420d03f60a04bf2cb8129024977c795679b072bcaf89afde9a771fd9930810
        b38bae12dccf3f2e5512721f2e6b7124501adde69f84cd877a5847187408da17bc9f9abce94b7d8cec7aec3adb851dfa
        63094366c464c3d2ef1c18473215d908dd433b3724c2ba1612a14d432a65c45150940002133ae4dd71dff89e10314e55
        81ac77d65f11199b043556f1d7a3c76b3c11183b5924a509f28fe6ed97f1fbfa9ebabf2c1e153c6e86e34570eae96fb1
        860e5e0a5a3e2ab3771fe71c4e3d06fa2965dcb999e71d0f803e89d65266c8252e4cc9789c10b36ac6150eba94e2ea78
        a5fc3c531e0a2df4f2f74ea7361d2b3d1939260f19c279605223a708f71312b6ebadfe6eeac31f66e3bc4595a67bc883
        b17f37d1018cff28c332ddefbe6c5aa56558218568ab9802eecea50fdb2f953b2aef7dad5b6e2f841521b62829076170
        ecdd4775619f151013cca830eb61bd960334fe1eaa0363cfb5735c904c70a239d59e9e0bcbaade14eecc86bc60622ca7
        9cab5cabb2f3846e648b1eaf19bdf0caa02369b9655abb5040685a323c2ab4b3319ee9d5c021b8f79b540b19875fa099
        95f7997e623d7da8f837889a97e32d7711ed935f166812810e358829c7e61fd696dedfa17858ba9957f584a51b227263
        9b83c3ff1ac24696cdb30aeb532e30548fd948e46dbc312858ebf2ef34c6ffeafe28ed61ee7c3c735d4a14d9e864b7e3
        42105d14203e13e045eee2b6a3aaabeadb6c4f15facb4fd0c742f442ef6abbb5654f3b1d41cd2105d81e799e86854dc7
        e44b476a3d816250cf62a1f25b8d2646fc8883a0c1c7b6a37f1524c369cb749247848a0b5692b285095bbf00ad19489d
        1462b17423820e0058428d2a0c55f5ea1dadf43e233f70613372f0928d937e41d65fecf16c223bdb7cde3759cbee7460
        4085f2a7ce77326ea607808419f8509ee8efd85561d99735a969a7aac50c06c25a04abfc800bcadc9e447a2ec3453484
        fdd567050e1e9ec9db73dbd3105588cd675fda79e3674340c5c43465713e38d83d28f89ef16dff20153e21e78fb03d4a
        e6e39f2bdb83adf7e93d5a68948140f7f64c261c94692934411520f77602d4f7bcf46b2ed4a20068d40824713320f46a
        43b7d4b7500061af1e39f62e9724454614214f74bf8b88404d95fc1d96b591af70f4ddd366a02f45bfbc09ec03bd9785
        7fac6dd031cb850496eb27b355fd3941da2547e6abca0a9a28507825530429f40a2c86dae9b66dfb68dc1462d7486900
        680ec0a427a18dee4f3ffea2e887ad8cb58ce0067af4d6b6aace1e7cd3375fecce78a399406b2a4220fe9e35d9f385b9
        ee39d7ab3b124e8b1dc9faf74b6d185626a36631eae397b23a6efa74dd5b43326841e7f7ca7820fbfb0af54ed8feb397
        454056acba48952755533a3a20838d87fe6ba9b7d096954b55a867bca1159a58cca9296399e1db33a62a4a563f3125f9
        5ef47e1c9029317cfdf8e80204272f7080bb155c05282ce395c11548e4c66d2248c1133fc70f86dc07f9c9ee41041f0f
        404779a45d886e17325f51ebd59bc0d1f2bcc18f41113564257b7834602a9c60dff8e8a31f636c1b0e12b4c202e1329e
        af664fd1cad181156b2395e0333e92e13b240b62eebeb92285b2a20ee6ba0d99de720c8c2da2f728d012784595b794fd
        647d0862e7ccf5f05449a36f877d48fac39dfd27f33e8d1e0a476341992eff743a6f6eabf4f8fd37a812dc60a1ebddf8
        991be14cdb6e6b0dc67b55106d672c372765d43bdcd0e804f1290dc7cc00ffa3b5390f92690fed0b667b9ffbcedb7d9c
        a091cf0bd9155ea3bb132f88515bad247b9479bf763bd6eb37392eb3cc1159798026e297f42e312d6842ada7c66a2b3b
        12754ccc782ef11c6a124237b79251e706a1bbe64bfb63501a6b101811caedfa3d25bdd8e2e1c3c9444216590a121386
        d90cec6ed5abea2a64af674eda86a85fbebfe98864e4c3fe9dbc8057f0f7c08660787bf86003604dd1fd8346f6381fb0
        7745ae04d736fccc83426b33f01eab71b08041873c005e5f77a057bebde8ae2455464299bf582e614e58f48ff2ddfda2
        f474ef388789bdc25366f9c3c8b38e74b475f25546fcd9b97aeb26618b1ddf84846a0e79915f95e2466e598e20b45770
        8cd55591c902de4cb90bace1bb8205d011a862487574a99eb77f19b6e0a9dc09662d09a1c4324633e85a1f0209f0be8c
        4a99a0251d6efe101ab93d1d0ba5a4dfa186f20f2868f169dcb7da83573906fea1e2ce9b4fcd7f5250115e01a70683fa
        a002b5c40de6d0279af88c27773f8641c3604c0661a806b5f0177a28c0f586e0006058aa30dc7d6211e69ed72338ea63
        53c2dd94c2c21634bbcbee5690bcb6deebfc7da1ce591d766f05e4094b7c018839720a3d7c927c2486e3725f724d9db9
        1ac15bb4d39eb8fced54557808fca5b5d83d7cd34dad0fc41e50ef5eb161e6f8a28514d96c51133c6fd5c7e756e14ec4
        362abfceddc6c837d79a323492638212670efa8e406000e03a39ce37d3faf5cfabc277375ac52d1b5cb0679e4fa33742
        d382274099bc9bbed5118e9dbf0f7315d62d1c7ec700c47bb78c1b6b21a19045b26eb1be6a366eb45748ab2fbc946e79
        c6a376d26549c2c8530ff8ee468dde7dd5730a1d4cd04dc62939bbdba9ba4650ac9526e8be5ee304a1fad5f06a2d519a
        63ef8ce29a86ee22c089c2b843242ef6a51e03aa9cf2d0a483c061ba9be96a4d8fe51550ba645bd62826a2f9a73a3ae1
        4ba99586ef5562e9c72fefd3f752f7da3f046f6977fa0a5980e4a91587b086019b09e6ad3b3ee593e990fd5a9e34d797
        2cf0b7d9022b8b5196d5ac3a017da67dd1cf3ed67c7d2d281f9f25cfadf2b89b5ad6b4725a88f54ce029ac71e019a5e6
        47b0acfded93fa9be8d3c48d283b57ccf8d5662979132e28785f0191ed756055f7960e44e3d35e8c15056dd488f46dba
        03a161250564f0bdc3eb9e153c9057a297271aeca93a072a1b3f6d9b1e6321f5f59c66fb26dcf3197533d928b155fdf5
        035634828aba3cbb28517711c20ad9f8abcc5167ccad925f4de817513830dc8e379d58629320f991ea7a90c2fb3e7bce
        5121ce64774fbe32a8b6e37ec3293d4648de53696413e680a2ae0810dd6db22469852dfd09072166b39a460a6445c0dd
        586cdecf1c20c8ae5bbef7dd1b588d40ccd2017f6bb4e3bbdda26a7e3a59ff453e350a44bcb4cdd572eacea8fa6484bb
        8d6612aebf3c6f47d29be463542f5d9eaec2771bf64e6370740e0d8de75b1357f8721671af537d5d4040cb084eb4e2cc
        34d2466a0115af84e1b0042895983a1d06b89fb4ce6ea0486f3f3b823520ab82011a1d4b277227f8611560b1e7933fdc
        bb3a792b344525bda08839e151ce794b2f32c9b7a01fbac9e01cc87ebcc7d1f6cf0111c3a1e8aac71a908749d44fbd9a
        d0dadecbd50ada380339c32ac69136678df9317ce0b12b4ff79e59b743f5bb3af2d519ff27d9459cbf97222c15e6fc2a
        0f91fc719b941525fae59361ceb69cebc2a8645912baa8d1b6c1075ee3056a0c10d25065cb03a442e0ec6e0e1698db3b
        4c98a0be3278e9649f1f9532e0d392dfd3a0342b8971f21e1b0a74414ba3348cc5be7120c37632d8df359f8d9b992f2e
        e60b6f470fe3f11de54cda541edad891ce6279cfcd3e7e6f1618b166fd2c1d05848fd2c5f6fb2299f523f357a6327623
        93a8353156cccd02acf081625a75ebb56e16369788d273ccde96629281b949d04c50901b71c65614e6c6c7bd327a140a
        45e1d006c3f27b9ac9aa53fd62a80f00bb25bfe235bdd2f671126905b2040222b6cbcf7ccd769c2b53113ec01640e3d3
        38abbd602547adf0ba38209cf746ce7677afa1c52075606085cbfe4e8ae88dd87aaaf9b04cf9aa7e1948c25c02fb8a8c
        01c36ae4d6ebe1f990d4f869a65cdea03f09252dc208e69fb74e6132ce77e25b578fdfe33ac372e6
    `.replace(/\s+/g, "");
    const PI_WORDS = Uint32Array.from({ length: PI_HEX.length / 8 }, (_, i) => parseInt(PI_HEX.substr(i * 8, 8), 16));

    class Blowfish {
        constructor() {
            this.p = PI_WORDS.slice(0, 18);
            this.s = PI_WORDS.slice(18);
        }

        f(x) {
            const s = this.s;
            return (((s[x >>> 24] + s[256 + ((x >>> 16) & 255)]) ^ s[512 + ((x >>> 8) & 255)]) + s[768 + (x & 255)]) >>> 0;
        }

        /** Encrypts the block in lr[0], lr[1] in place. */
        encipher(lr) {
            const p = this.p;
            let l = lr[0] ^ p[0];
            let r = lr[1];
            for (let i = 1; i <= 16; i += 2) {
                r ^= this.f(l >>> 0) ^ p[i];
                l ^= this.f(r >>> 0) ^ p[i + 1];
            }
            lr[0] = (r ^ p[17]) >>> 0;
            lr[1] = l >>> 0;
        }

        /** The eksblowfish key schedule; without `data` this is Blowfish_expand0state. */
        expand(key, data) {
            const nextKey = wordStream(key);
            const nextData = data ? wordStream(data) : () => 0;
            for (let i = 0; i < 18; i++) this.p[i] ^= nextKey();
            const lr = new Uint32Array(2);
            const fill = (table, count) => {
                for (let i = 0; i < count; i += 2) {
                    lr[0] ^= nextData();
                    lr[1] ^= nextData();
                    this.encipher(lr);
                    table[i] = lr[0];
                    table[i + 1] = lr[1];
                }
            };
            fill(this.p, 18);
            fill(this.s, 1024);
        }
    }

    /** Big-endian 32-bit words from `bytes`, wrapping around at the end (Blowfish_stream2word). */
    function wordStream(bytes) {
        let j = 0;
        return () => {
            let word = 0;
            for (let i = 0; i < 4; i++) {
                word = (word << 8) | bytes[j];
                j = (j + 1) % bytes.length;
            }
            return word >>> 0;
        };
    }

    const MAGIC = new TextEncoder().encode("OxychromaticBlowfishSwatDynamite");

    function bcryptHash(sha2pass, sha2salt) {
        const bf = new Blowfish();
        bf.expand(sha2pass, sha2salt);
        for (let i = 0; i < 64; i++) {
            bf.expand(sha2salt);
            bf.expand(sha2pass);
        }
        const next = wordStream(MAGIC);
        const cdata = Uint32Array.from({ length: 8 }, next);
        const block = new Uint32Array(2);
        for (let i = 0; i < 64; i++) {
            for (let j = 0; j < 8; j += 2) {
                block[0] = cdata[j];
                block[1] = cdata[j + 1];
                bf.encipher(block);
                cdata[j] = block[0];
                cdata[j + 1] = block[1];
            }
        }
        const out = new Uint8Array(32);
        for (let i = 0; i < 8; i++) {
            // little-endian, as in the reference implementation
            out[4 * i] = cdata[i];
            out[4 * i + 1] = cdata[i] >>> 8;
            out[4 * i + 2] = cdata[i] >>> 16;
            out[4 * i + 3] = cdata[i] >>> 24;
        }
        return out;
    }

    const sha512 = async (data) => new Uint8Array(await crypto.subtle.digest("SHA-512", data));

    async function bcryptPbkdf(password, salt, length, rounds) {
        const stride = Math.ceil(length / 32);
        const amount = Math.ceil(length / stride);
        const key = new Uint8Array(length);
        const sha2pass = await sha512(password);
        const countSalt = new Uint8Array(salt.length + 4);
        countSalt.set(salt);
        for (let count = 1, remaining = length; remaining > 0; count++) {
            new DataView(countSalt.buffer).setUint32(salt.length, count);
            let tmp = bcryptHash(sha2pass, await sha512(countSalt));
            const out = tmp.slice();
            for (let r = 1; r < rounds; r++) {
                tmp = bcryptHash(sha2pass, await sha512(tmp));
                for (let j = 0; j < out.length; j++) out[j] ^= tmp[j];
            }
            let i = 0;
            for (; i < Math.min(amount, remaining); i++) {
                const dest = i * stride + (count - 1);
                if (dest >= length) break;
                key[dest] = out[i];
            }
            remaining -= i;
        }
        return key;
    }

    // --- key file formats ----------------------------------------------------------------------

    class Reader {
        constructor(bytes) { this.bytes = bytes; this.at = 0; }
        uint32() {
            if (this.at + 4 > this.bytes.length) throw new Error("the key file is truncated");
            const v = new DataView(this.bytes.buffer, this.bytes.byteOffset).getUint32(this.at);
            this.at += 4;
            return v;
        }
        bytesOf(n) {
            if (this.at + n > this.bytes.length) throw new Error("the key file is truncated");
            const b = this.bytes.subarray(this.at, this.at + n);
            this.at += n;
            return b;
        }
        string() { return this.bytesOf(this.uint32()); }
        text() { return new TextDecoder().decode(this.string()); }
    }

    function pem(text, label) {
        const match = new RegExp(`-----BEGIN ${label}-----([^-]+)-----END ${label}-----`).exec(text);
        if (!match) return null;
        return Uint8Array.from(atob(match[1].replace(/\s+/g, "")), (c) => c.charCodeAt(0));
    }

    const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

    function concat(...parts) {
        const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
        let at = 0;
        for (const p of parts) {
            out.set(p, at);
            at += p.length;
        }
        return out;
    }

    /** SSH wire encoding: string = uint32 length + bytes; mpint = minimal two's complement. */
    function sshString(bytes) {
        if (typeof bytes === "string") bytes = new TextEncoder().encode(bytes);
        const out = new Uint8Array(4 + bytes.length);
        new DataView(out.buffer).setUint32(0, bytes.length);
        out.set(bytes, 4);
        return out;
    }
    function sshMpint(unsigned) {
        let i = 0;
        while (i < unsigned.length - 1 && unsigned[i] === 0) i++;
        const trimmed = unsigned.subarray(i);
        return sshString(trimmed[0] & 0x80 ? concat([0], trimmed) : trimmed);
    }

    const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const unb64url = (text) => Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const toBigInt = (bytes) => bytes.length ? BigInt("0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")) : 0n;
    function fromBigInt(n) {
        let hex = n.toString(16);
        if (hex.length % 2) hex = "0" + hex;
        return Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
    }

    const RSA_MIN_BITS = 2048;
    const RSA_SIGN = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    // PKCS#8 header for an RSA key: version 0, AlgorithmIdentifier rsaEncryption with NULL parameters.
    const PKCS8_RSA_HEADER = Uint8Array.from([0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);

    function derLength(n) {
        if (n < 0x80) return Uint8Array.of(n);
        const bytes = fromBigInt(BigInt(n));
        return concat([0x80 | bytes.length], bytes);
    }
    const der = (tag, body) => concat([tag], derLength(body.length), body);

    /** Wraps a PKCS#1 RSAPrivateKey into PKCS#8, which WebCrypto imports. */
    const pkcs1ToPkcs8 = (pkcs1) => der(0x30, concat(PKCS8_RSA_HEADER, der(0x04, pkcs1)));

    /**
     * Imports an RSA private key (PKCS#8 or JWK), checks it, and returns it in the common shape:
     * PKCS#8 for storage plus the SSH public key blob.
     */
    async function rsaKey(format, keyData, expected) {
        let key;
        try {
            key = await crypto.subtle.importKey(format, keyData, RSA_SIGN, true, ["sign"]);
        } catch (e) {
            throw new Error("the RSA key couldn't be read (" + e.message + ")");
        }
        const jwk = await crypto.subtle.exportKey("jwk", key);
        const n = unb64url(jwk.n);
        const e = unb64url(jwk.e);
        const bits = toBigInt(n).toString(2).length;
        if (bits < RSA_MIN_BITS) throw new Error(`RSA keys need at least ${RSA_MIN_BITS} bits, this one has ${bits}`);
        if (expected && (toBigInt(n) !== expected.n || toBigInt(e) !== expected.e)) {
            throw new Error("the key file is inconsistent (public key doesn't match)");
        }
        // A sign/verify round trip catches private parts that don't belong to the public key.
        const probe = crypto.getRandomValues(new Uint8Array(32));
        const signature = await crypto.subtle.sign(RSA_SIGN, key, probe);
        const pub = await crypto.subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e }, RSA_SIGN, false, ["verify"]);
        if (!await crypto.subtle.verify(RSA_SIGN, pub, signature, probe)) {
            throw new Error("the key file is inconsistent (private key doesn't match)");
        }
        const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key));
        return { type: "ssh-rsa", pkcs8, publicKey: concat(sshString("ssh-rsa"), sshMpint(e), sshMpint(n)), bits };
    }

    async function ed25519Key(seed, expectedPublic) {
        const pkcs8 = concat(PKCS8_ED25519, seed);
        seed.fill(0);
        // WebCrypto derives the public key; it must match the one in the file.
        const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
        const raw = unb64url((await crypto.subtle.exportKey("jwk", key)).x);
        if (expectedPublic && !equal(raw, expectedPublic)) {
            throw new Error("the key file is inconsistent (public key doesn't match)");
        }
        return { type: "ssh-ed25519", pkcs8, publicKey: concat(sshString("ssh-ed25519"), sshString(raw)) };
    }
    const PKCS8_ED25519 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20]);
    const OPENSSH_MAGIC = new TextEncoder().encode("openssh-key-v1\0");
    // name: [WebCrypto algorithm, key length, IV length]
    const CIPHERS = {
        "aes128-ctr": ["AES-CTR", 16, 16],
        "aes192-ctr": ["AES-CTR", 24, 16],
        "aes256-ctr": ["AES-CTR", 32, 16],
        "aes128-gcm@openssh.com": ["AES-GCM", 16, 12],
        "aes256-gcm@openssh.com": ["AES-GCM", 32, 12],
    };

    async function readOpenSsh(der, passphrase) {
        if (!equal(der.subarray(0, OPENSSH_MAGIC.length), OPENSSH_MAGIC)) throw new Error("not an OpenSSH key file");
        const r = new Reader(der.subarray(OPENSSH_MAGIC.length));
        const cipher = r.text();
        const kdf = r.text();
        const kdfOptions = new Reader(r.string());
        if (r.uint32() !== 1) throw new Error("the file holds more than one key");
        r.string(); // public key
        let section = r.string();
        // AEAD ciphers append their tag after the encrypted section; WebCrypto wants it on the end.
        if (CIPHERS[cipher]?.[0] === "AES-GCM") {
            const withTag = new Uint8Array(section.length + 16);
            withTag.set(section);
            withTag.set(r.bytesOf(16), section.length);
            section = withTag;
        }

        if (cipher !== "none") {
            if (!(cipher in CIPHERS) || kdf !== "bcrypt") {
                throw new Error(`unsupported key encryption ${cipher}/${kdf}`);
            }
            if (!passphrase) throw new Error("this key is protected: enter its passphrase");
            const salt = kdfOptions.string();
            const rounds = kdfOptions.uint32();
            const [algorithm, keyLength, ivLength] = CIPHERS[cipher];
            const derived = await bcryptPbkdf(new TextEncoder().encode(passphrase), salt, keyLength + ivLength, rounds);
            const aes = await crypto.subtle.importKey("raw", derived.subarray(0, keyLength), algorithm, false, ["decrypt"]);
            const iv = derived.subarray(keyLength);
            try {
                section = new Uint8Array(await crypto.subtle.decrypt(algorithm === "AES-GCM"
                    ? { name: algorithm, iv }
                    : { name: algorithm, counter: iv, length: 128 }, aes, section));
            } catch (e) {
                throw new Error("wrong passphrase"); // GCM fails authentication instead of producing garbage
            } finally {
                derived.fill(0);
            }
        }

        const p = new Reader(section);
        if (p.uint32() !== p.uint32()) throw new Error("wrong passphrase");
        const type = p.text();
        let result;
        if (type === "ssh-ed25519") {
            const publicKey = p.string().slice();
            const seed = p.string().slice(0, 32); // seed || public key
            result = await ed25519Key(seed, publicKey);
        } else if (type === "ssh-rsa") {
            const [n, e, d, iqmp, prime1, prime2] = Array.from({ length: 6 }, () => toBigInt(p.string()));
            const jwk = {
                kty: "RSA",
                n: b64url(fromBigInt(n)), e: b64url(fromBigInt(e)), d: b64url(fromBigInt(d)),
                p: b64url(fromBigInt(prime1)), q: b64url(fromBigInt(prime2)),
                dp: b64url(fromBigInt(d % (prime1 - 1n))), dq: b64url(fromBigInt(d % (prime2 - 1n))),
                qi: b64url(fromBigInt(iqmp)),
            };
            result = await rsaKey("jwk", jwk, { n, e });
        } else {
            throw new Error(`only Ed25519 and RSA keys can be imported, this is ${type}`);
        }
        result.comment = p.text();
        section.fill(0);
        return result;
    }

    /**
     * Parses a private key file. Returns { type, pkcs8, publicKey, comment }: the key in the PKCS#8 form
     * WebCrypto imports and its SSH public key blob. Throws an Error with a user-facing message otherwise.
     */
    async function read(text, passphrase) {
        const encryptedPem = /Proc-Type: 4,ENCRYPTED|-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(text);
        if (encryptedPem) {
            throw new Error("this PEM file is passphrase-protected in the old format; convert it on your computer "
                + "with `ssh-keygen -p -f <file>` (keeps a passphrase, writes the OpenSSH format) and import that");
        }
        const openssh = pem(text, "OPENSSH PRIVATE KEY");
        if (openssh) return readOpenSsh(openssh, passphrase);

        const pkcs1 = pem(text, "RSA PRIVATE KEY");
        if (pkcs1) return { ...await rsaKey("pkcs8", pkcs1ToPkcs8(pkcs1)), comment: "" };

        const pkcs8 = pem(text, "PRIVATE KEY");
        if (pkcs8) {
            if (pkcs8.length === 48 && equal(pkcs8.subarray(0, 16), PKCS8_ED25519)) {
                return { ...await ed25519Key(pkcs8.slice(16)), comment: "" };
            }
            return { ...await rsaKey("pkcs8", pkcs8), comment: "" };
        }
        if (/-----BEGIN (EC|DSA) PRIVATE KEY-----/.test(text)) {
            throw new Error("only Ed25519 and RSA keys can be imported");
        }
        throw new Error("that doesn't look like a private key file");
    }

    window.sshaKeyImport = { read, bcryptPbkdf };
})();
