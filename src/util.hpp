#include <fstream>

#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libff/algebra/curves/public_params.hpp"

using namespace libsnark;
using namespace libff;
using namespace std;

template<typename ppT>
void print_vk_to_file(r1cs_ppzksnark_verification_key<ppT> vk, string pathToFile)
{
  ofstream vk_data;
  vk_data.open(pathToFile);
  vk_data << vk;
  vk_data.close();
}

template<typename ppT>
void read_vk_from_file(r1cs_ppzksnark_verification_key<ppT> &vk, string pathToFile)
{
    ifstream vk_data;
    vk_data.open(pathToFile);
    vk_data >> vk;
    vk_data.close();
}

template<typename ppT>
void print_proof_to_file(r1cs_ppzksnark_proof<ppT> proof, string pathToFile)
{
  ofstream proof_data;
  proof_data.open(pathToFile);
  proof_data << proof;

  proof_data.close();
}

template<typename ppT>
void read_proof_from_file(r1cs_ppzksnark_proof<ppT> &proof, string pathToFile)
{
    ifstream proof_data;
    proof_data.open(pathToFile);
    proof_data >> proof;

    proof_data.close();
}