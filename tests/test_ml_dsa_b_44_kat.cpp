#include "ml_dsa/ml_dsa_44.hpp"
#include "test_helper.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <gtest/gtest.h>

#include <iostream>
#include <ostream>
#include <iomanip>

using namespace std::literals;

template <typename T, std::size_t N>
void hexdump_array_to_file(const std::string& filename,
                           const std::string& label,
                           const std::array<T, N>& data)
{
    std::ofstream out(filename, std::ios::app);
    if (!out.is_open()) {
        return;
    }

    out << label << " (" << N << " bytes):\n";

    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < N; ++i) {
        out << std::setw(2) << static_cast<int>(data[i]);
        if ((i + 1) % 16 == 0)
            out << '\n';
        else
            out << ' ';
    }
    out << "\n\n";
}

// Use ML-DSA-44 key generation known answer tests (KATs) from NIST ACVP Server to ensure functional correctness and compatibility
// of this ML-DSA library implementation with ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
TEST(ML_DSA, ML_DSA_44_Keygen_ACVP_KnownAnswerTests)
{
  const std::string kat_file = "./kats/ml_dsa_b_44_key-gen.kat";
  std::fstream file(kat_file);

  //while (true) {
    std::string seed_line;

    if (!std::getline(file, seed_line).eof()) {
      std::string pkey_line;
      std::string skey_line;

      std::getline(file, pkey_line);
      std::getline(file, skey_line);

      const auto seed = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<ml_dsa_44::KeygenSeedByteLen>(seed_line);
      const std::array<uint8_t, ml_dsa_44::PubKeyByteLen> pkey = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<ml_dsa_44::PubKeyByteLen>(pkey_line);
      const std::array<uint8_t, ml_dsa_44::SecKeyByteLen> skey = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<ml_dsa_44::SecKeyByteLen>(skey_line);

      std::array<uint8_t, ml_dsa_44::PubKeyByteLen> computed_pkey{};
      std::array<uint8_t, ml_dsa_44::SecKeyByteLen> computed_skey{};

      ml_dsa_44::keygen(seed, computed_pkey, computed_skey);

      if (std::memcmp(pkey.data(), computed_pkey.data(), pkey.size()) == 0)
        std::cout << true << std::endl;

        
      EXPECT_EQ(pkey, computed_pkey);
      EXPECT_EQ(skey, computed_skey);
      ASSERT_EQ(pkey.size(), computed_pkey.size());
      ASSERT_EQ(skey.size(), computed_skey.size());
      hexdump_array_to_file("expected.txt", "Expected pkey", skey);
      hexdump_array_to_file("computed.txt", "Computed pkey", computed_skey);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      //break;
    }
  //}

  file.close();
}

// Use ML-DSA-44 sign known answer tests (KATs) from NIST ACVP Server to ensure functional correctness and compatibility
// of this ML-DSA library implementation with ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
TEST(ML_DSA, ML_DSA_44_Sign_ACVP_KnownAnswerTests)
{
  const std::string kat_file = "./kats/ml_dsa_b_44_sig-gen.kat";
  std::fstream file(kat_file);

  while (true) {
    std::string skey_line;

    if (!std::getline(file, skey_line).eof()) {
      std::string msg_line;
      std::string rnd_line;
      std::string sig_line;

      std::getline(file, msg_line);
      std::getline(file, rnd_line);
      std::getline(file, sig_line);

      const auto msg = ml_dsa_test_helper::extract_and_parse_variable_length_hex_string(msg_line);
      const auto skey = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<ml_dsa_44::SecKeyByteLen>(skey_line);
      std::array<uint8_t, ml_dsa_44::SigningSeedByteLen> rnd;
      std::cout << rnd_line << std::endl;
      if (rnd_line.length() == ml_dsa_44::SigningSeedByteLen) {
        std::cout << rnd_line << std::endl;
        rnd = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<ml_dsa_44::SigningSeedByteLen>(rnd_line);
      } else {
        rnd.fill(0);
      }
      const auto sig = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<ml_dsa_44::SigByteLen>(sig_line);
      const auto ctx = std::span<const uint8_t>{};

      std::array<uint8_t, ml_dsa_44::SigByteLen> computed_sig{};
      ml_dsa_44::sign(rnd, skey, msg, ctx, computed_sig);

      EXPECT_EQ(sig, computed_sig);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

// Use ML-DSA-44 verify known answer tests (KATs) from NIST ACVP Server to ensure functional correctness and compatibility
// of this ML-DSA library implementation with ML-DSA standard @ https://doi.org/10.6028/NIST.FIPS.204.
TEST(ML_DSA, ML_DSA_44_Verify_ACVP_KnownAnswerTests)
{
  const std::string kat_file = "./kats/ml_dsa_b_44_sig-ver.kat";
  std::fstream file(kat_file);

  while (true) {
    std::string pkey_line;

    if (!std::getline(file, pkey_line).eof()) {
      std::string skey_line;
      std::string testPassed_line;
      std::string msg_line;
      std::string sig_line;
      std::string reason_line;

      std::getline(file, skey_line);
      std::getline(file, testPassed_line);
      std::getline(file, msg_line);
      std::getline(file, sig_line);
      std::getline(file, reason_line);

      const auto msg = ml_dsa_test_helper::extract_and_parse_variable_length_hex_string(msg_line);
      const auto pkey = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<ml_dsa_44::PubKeyByteLen>(pkey_line);
      const auto ctx = std::span<const uint8_t>{};
      const auto sig = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<ml_dsa_44::SigByteLen>(sig_line);
      const auto test_passed = testPassed_line.substr(testPassed_line.find("="sv) + 2, testPassed_line.size()) == "True";

      const auto is_valid = ml_dsa_44::verify(pkey, msg, ctx, sig);
      printf("%d\n", is_valid == test_passed);

      if (test_passed) {
        EXPECT_TRUE(is_valid);
      } else {
        EXPECT_FALSE(is_valid);
      }

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}
