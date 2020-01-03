import nacl.signing, nacl.encoding

import ecvrf_edwards25519_sha512_elligator2, ed25519


# A.4. ECVRF-EDWARDS25519-SHA512-Elligator2

# Setup data for first testcase
secret_key = bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
public_key = ed25519.get_public_key(secret_key)
assert public_key == bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
pi_string = bytes.fromhex('b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f061560f55edc256a787afe701677c0f602900')
beta_string = bytes.fromhex('5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc')

# print("Testing mult...  ", end='')
# H = ed25519.i_decode_point(bytes.fromhex('1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7'))
# x = secret_key
# Gamma = ed25519.i_scalar_mult(H, x)
# assert ed25519.i_encode_point(Gamma) == bytes.fromhex('b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7')
# print("  ...pass\n\n")


print("1. Testing prove", end='')
res_pi = ecvrf_edwards25519_sha512_elligator2.ecvrf_prove(alpha_string=b'', secret_key=secret_key)
assert res_pi == pi_string
print("  ...pass\n\n")


print("2. Testing proof-to-hash", end='')
res_beta = ecvrf_edwards25519_sha512_elligator2.ecvrf_proof_to_hash(pi_string=pi_string)
assert res_beta == beta_string
print("  ...pass\n\n")

print("3. Testing verify", end='')
res_valid = ecvrf_edwards25519_sha512_elligator2.ecvrf_verify(public_key=public_key, pi_string=pi_string, alpha_string=b'')
assert res_valid == "VALID"
print("  ...pass\n\n")


# PK = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
# alpha = (the empty string)
# x = 307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f
# In Elligator: r = 9ddd071cd5837e591a3a40c57a46701bb7f49b1b53c670d490c2766a08fa6e3d
# In Elligator: w = c7b5d6239e52a473a2b57a92825e0e5de4656e349bb198de5afd6a76e5a07066
# In Elligator: e = -1
# H = 1c5672d919cc0a800970cd7e05cb36ed27ed354c33519948e5a9eaf89aee12b7
# k = 868b56b8b3faf5fc7e276ff0a65aaa896aa927294d768d0966277d94599b7afe4  a6330770da5fdc2875121e0cbecbffbd4ea5e491eb35be53fa7511d9f5a61f2
# U = k*B = c4743a22340131a2323174bfc397a6585cbe0cc521bfad09f34b11dd4bcf5936
# V = k*H = e309cf5272f0af2f54d9dc4a6bad6998a9d097264e17ae6fce2b25dcbdd10e8b
# pi =      b6b4699f87d56126c9117a7da55bd0085246f4c56dbc95d20172612e9d38e8d7
#           ca65e573a126ed88d4e30a46f80a666854d675cf3ba81de0de043c3774f06156
#           0f55e dc256a787afe701677c0f602900
# beta = 5b49b554d05c0cd5a5325376b3387de59d924fd1e13ded44648ab33c21349a 603f25b84ec5ed887995b33da5e3bfcb87cd2f64521c4c62cf825cffabbe5d31cc


# SK = 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb
# PK = 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
# alpha = 72 (1 byte)
# x = 68bd9ed75882d52815a97585caf4790a7f6c6b3b7f821c5e259a24b02e502e51
# In Elligator: r = 92181bd612695e464049590eb1f9746750d6057441789c9759af8308ac77fd4a
# In Elligator: w = 7ff6d8b773bfbae57b2ab9d49f9d3cb7d9af40a03d3ed3c6beaaf2d486b1fe6e
# In Elligator: e = 1
# H = 86725262c971bf064168bca2a87f593d425a49835bd52beb9f52ea59352d80fa
# k = fd919e9d43c61203c4cd948cdaea0ad4488060db105d25b8fb4a5da2bd40e4b83 30ca44a0538cc275ac7d568686660ccfd6323c805b917e91e28a4ab352b9575
# U = k*B = 04b1ba4d8129f0d4cec522b0fd0dff84283401df791dcc9b93a219c51cf27324
# V = k*H = ca8a97ce1947d2a0aaa280f03153388fa7aa754eedfca2b4a7ad405707599ba5
# pi = ae5b66bdf04b4c010bfe32b2fc126ead2107b697634f6f7337b9bff8785ee111 200095ece87dde4dbe87343f6df3b107d91798c8a7eb1245d3bb9c5aafb093358c13e 6ae1111a55717e895fd15f99f07
# beta = 94f4487e1b2fec954309ef1289ecb2e15043a2461ecc7b2ae7d4470607ef82 eb1cfa97d84991fe4a7bfdfd715606bc27e2967a6c557cfb5875879b671740b7d8


# SK = c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7
# PK = fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
# alpha = af82 (2 bytes)
# x = 909a8b755ed902849023a55b15c23d11ba4d7f4ec5c2f51b1325a181991ea95c
# In Elligator: r = dcd7cda88d6798599e07216de5a48a27dcd1cde197ab39ccaf6a906ae6b25c7f
# In Elligator: w = 2ceaa2c2ff3028c34f9fbe076ff99520b925f18d652285b4daad5ccc467e523b
# In Elligator: e = -1
# H = 9d8663faeb6ab14a239bfc652648b34f783c2e99f758c0e1b6f4f863f9419b56
# k = 8f675784cdc984effc459e1054f8d386050ec400dc09d08d2372c6fe0850eaaa5 0defd02d965b79930dcbca5ba9222a3d99510411894e63f66bbd5d13d25db4b
# U = k*B = d6f8a95a4ce86812e3e50febd9d48196b3bc5d1d9fa7b6dfa33072641b45d029
# V = k*H = f77cd4ce0b49b386e80c3ce404185f93bb07463600dc14c31b0a09beaff4d592
# pi = dfa2cba34b611cc8c833a6ea83b8eb1bb5e2ef2dd1b0c481bc42ff36ae7847f6 ab52b976cfd5def172fa412defde270c8b8bdfbaae1c7ece17d9833b1bcf31064fff7 8ef493f820055b561ece45e1009
# beta = 2031837f582cd17a9af9e0c7ef5a6540e3453ed894b62c293686ca3c1e319d de9d0aa489a4b59a9594fc2328bc3deff3c8a0929a369a72b1180a596e016b5ded




