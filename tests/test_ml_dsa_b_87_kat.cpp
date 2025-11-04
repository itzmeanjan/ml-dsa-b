#include "ml_dsa_b/ml_dsa_b_87.hpp"
#include "test_helper.hpp"
#include <array>
#include <cstdint>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>

using namespace std::literals;
using namespace ml_dsa_b_87;

TEST(ML_DSA_B, ML_DSA_B_87_Keygen_KnownAnswerTests)
{
  const std::string kat_file = "./kats/ml_dsa_b_87_key-gen.kat";
  std::fstream file(kat_file);

  while (true) {
    std::string seed_line;

    if (!std::getline(file, seed_line).eof()) {
      std::string pkey_line;
      std::string skey_line;

      std::getline(file, pkey_line);
      std::getline(file, skey_line);

      const auto seed = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<KeygenSeedByteLen>(seed_line);
      const std::array<uint8_t, PubKeyByteLen> pkey = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<PubKeyByteLen>(pkey_line);
      const std::array<uint8_t, SecKeyByteLen> skey = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<SecKeyByteLen>(skey_line);

      std::array<uint8_t, PubKeyByteLen> computed_pkey{};
      std::array<uint8_t, SecKeyByteLen> computed_skey{};

      keygen(seed, computed_pkey, computed_skey);

      EXPECT_EQ(pkey, computed_pkey);
      EXPECT_EQ(skey, computed_skey);
      ASSERT_EQ(pkey.size(), computed_pkey.size());
      ASSERT_EQ(skey.size(), computed_skey.size());

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(ML_DSA_B, ML_DSA_B_87_Sign_KnownAnswerTests)
{
  const std::string kat_file = "./kats/ml_dsa_b_87_sig-gen.kat";
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
      const auto skey = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<SecKeyByteLen>(skey_line);

      std::array<uint8_t, SigningSeedByteLen> rnd{ 0 };
      if (rnd_line.length() >= SigningSeedByteLen) {
        rnd = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<SigningSeedByteLen>(rnd_line);
      }

      const auto sig = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<SigByteLen>(sig_line);

      std::array<uint8_t, SigByteLen> computed_sig{};
      sign_internal(rnd, skey, std::span(msg), computed_sig);

      EXPECT_EQ(sig, computed_sig);

      std::string empty_line;
      std::getline(file, empty_line);
    } else {
      break;
    }
  }

  file.close();
}

TEST(ML_DSA_B, ML_DSA_B_87_Verify_KnownAnswerTests)
{
  const std::string kat_file = "./kats/ml_dsa_b_87_sig-ver.kat";
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
      const auto pkey = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<PubKeyByteLen>(pkey_line);
      const auto sig = ml_dsa_test_helper::extract_and_parse_fixed_length_hex_string<SigByteLen>(sig_line);
      const auto test_passed = testPassed_line.substr(testPassed_line.find("="sv) + 2, testPassed_line.size()) == "True";

      const auto is_valid = verify_internal(pkey, msg, sig);

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
