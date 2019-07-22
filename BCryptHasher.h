/// @file   BCryptHasher.h
/// @date   2019.07.23
/// @author ttsuki

/// MIT License
/// 
/// Copyright(c) 2019 ttsuki
/// 
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files(the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions :
/// 
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
/// 
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.

#pragma once

#include <cstdint>
#include <vector>
#include <memory>

namespace BCryptHasher
{
	enum struct HashAlgorithm
	{
		Md5,
		Sha1,
		Sha256,
		Sha512,
	};

	class IHasher
	{
	public:
		virtual ~IHasher() = default;
		virtual void Update(const void* data, size_t dataLength) = 0;
		virtual std::vector<uint8_t> Finish() = 0;
		virtual std::vector<uint8_t> Value() const = 0;
	};

	std::unique_ptr<IHasher> CreateBCryptHasher(HashAlgorithm algorithm);
	std::unique_ptr<IHasher> CreateBCryptHmacSigner(HashAlgorithm algorithm, const void* secretKey, size_t secretKeyLength);

	inline std::unique_ptr<IHasher> CreateMd5Hasher() { return CreateBCryptHasher(HashAlgorithm::Md5); }
	inline std::unique_ptr<IHasher> CreateSha1Hasher() { return CreateBCryptHasher(HashAlgorithm::Sha1); }
	inline std::unique_ptr<IHasher> CreateSha256Hasher() { return CreateBCryptHasher(HashAlgorithm::Sha256); }
	inline std::unique_ptr<IHasher> CreateSha512Hasher() { return CreateBCryptHasher(HashAlgorithm::Sha512); }
	inline std::unique_ptr<IHasher> CreateHmacMd5Signer(const void* secretKey, size_t secretKeyLength) { return CreateBCryptHmacSigner(HashAlgorithm::Md5, secretKey, secretKeyLength); }
	inline std::unique_ptr<IHasher> CreateHmacSha1Signer(const void* secretKey, size_t secretKeyLength) { return CreateBCryptHmacSigner(HashAlgorithm::Sha1, secretKey, secretKeyLength); }
	inline std::unique_ptr<IHasher> CreateHmacSha256Signer(const void* secretKey, size_t secretKeyLength) { return CreateBCryptHmacSigner(HashAlgorithm::Sha256, secretKey, secretKeyLength); }
	inline std::unique_ptr<IHasher> CreateHmacSha512Signer(const void* secretKey, size_t secretKeyLength) { return CreateBCryptHmacSigner(HashAlgorithm::Sha512, secretKey, secretKeyLength); }
}
