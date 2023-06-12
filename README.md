**libsnark tutorial**

This tutorial is modified tutorial created by

*By Christian Lundkvist and Sam Mayo*

This is a tutorial intended to cover the very basics of the [libsnark](https://github.com/scipr-lab/libsnark) software library for creating zk-SNARKs. We will demonstrate how to formulate zk-SNARK circuits, create proofs and verify the proofs. The difference between my and their tutorial is that my tutorial serializes verification key and proof to file (aka sends file to Verifier) and then Verifier deserializes vk and proof and verify the SNARK.

Here we create proof for knowledge of root of:

x^3 + x + 5 == 35

The main focus of this tutorial is in section 2: libsnark components: 2. Gadgets

Steps are commented in libsnark-tutorial/src/test-gadget.cpp

Section 1. The Protoboard is preserved for completeness and may be skipped.

**Preliminaries**

For a more in-depth description of how zk-SNARKs work under the hood, please read Vitalik’s [three post introduction](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649).

**Quick intro to R1CS**

A *Rank One Constraint System* (R1CS) is a way to express a computation that makes it amenable to zero knowledge proofs. Basically any computation can be reduced (or flattened) to an R1CS. A single rank one constraint on a vector w is defined as

<A, w> \* <B,w> = <C, w>

Where A, B, C are vectors of the same length as w, and <> denotes inner product of vectors. A R1CS is then a system of these kinds of equations:

<A\_1, w> \* <B\_1,w> = <C\_1, w>

<A\_2, w> \* <B\_2,w> = <C\_2, w>

...

<A\_n, w> \* <B\_n,w> = <C\_n, w>

The vector w is called a *witness* and zk-SNARK proofs can always be reduced to proving that *the prover knows a witness w such that the R1CS is satisfied*.

**Building & running tests**

To install the dependencies:

On Debian 10 (buster), Ubuntu 18.04 LTS, Ubuntu 20.04 LTS:

`  `$ sudo apt install build-essential cmake git libgmp3-dev libprocps-dev python3-markdown libboost-program-options-dev libssl-dev python3 pkg-config

On Ubuntu 16.04 LTS:

sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev

In order to download and build the repo:

git clone https://github.com/vnovakovsky/libsnark-tutorial.git

cd libsnark-tutorial

/\*download libsnark sources to depends\*/

git submodule init && git submodule update

/\*in depends/libsnark/.gitmodules replace git: with https:\*/

/\*download dependencies of libsnark\*/

git submodule init && git submodule update

cd libsnark-tutorial

mkdir build && cd build && cmake ..

make

To run the tests go to the build directory and run:

./src/test-gadget

**libsnark components: 1. The Protoboard**

In electrical engineering, a *protoboard* or *prototyping board* is used to attach circuits and chips to quickly iterate on designs.

![Protoboard](Aspose.Words.83991abb-ceaa-41b8-a2c4-783efcdff4da.001.jpeg)

In the libsnark tool, the protoboard is where our "circuits" (i.e. R1CS and gadgets) will be collected.

The C++ file defining the protoboard is [here](https://github.com/scipr-lab/libsnark/blob/master/libsnark/gadgetlib1/protoboard.hpp). We will first show how to add R1CS to the protoboard.

Recall the example in [Vitalik’s blog post](https://medium.com/@VitalikButerin/quadratic-arithmetic-programs-from-zero-to-hero-f6d558cea649): We want to prove that we know a value x that satisfy the equation

x^3 + x + 5 == 35.

We can make this a little more general, and say that given a publicly known output value out, we want to prove that we know x such that

x^3 + x + 5 == out.

Recall that we can introduce some new variables sym\_1, y, sym\_2 and flatten the above equation into the following quadratic equations:

x \* x = sym\_1

sym\_1 \* x = y

y + x = sym\_2

sym\_2 + 5 = out

We can verify that the above system can be written as an R1CS with

w = [one, x, out, sym\_1, y, sym\_2]

and the vectors A\_1, ..., A\_4, B\_1, ..., B4, C\_1, ..., C\_4 are given by

A\_1 = [0, 1, 0, 0, 0, 0]

A\_2 = [0, 0, 0, 1, 0, 0]

A\_3 = [0, 1, 0, 0, 1, 0]

A\_4 = [5, 0, 0, 0, 0, 1]

B\_1 = [0, 1, 0, 0, 0, 0]

B\_2 = [0, 1, 0, 0, 0, 0]

B\_3 = [1, 0, 0, 0, 0, 0]

B\_4 = [1, 0, 0, 0, 0, 0]

C\_1 = [0, 0, 0, 1, 0, 0]

C\_2 = [0, 0, 0, 0, 1, 0]

C\_3 = [0, 0, 0, 0, 0, 1]

C\_4 = [0, 0, 1, 0, 0, 0]

The original degree 3 polynomial equation has a solution x=3 and we can verify that the R1CS has a corresponding solution

w = [1, 3, 35, 9, 27, 30].

Now let’s see how we can enter this R1CS into libsnark, produce proofs and verify them. We will use the pb\_variable type to declare our variables. See the file test.cpp for the full code.

First lets define the finite field where all our values live, and initialize the curve parameters:

typedef libff::Fr<default\_r1cs\_ppzksnark\_pp> FieldT;

default\_r1cs\_ppzksnark\_pp::init\_public\_params();

Next we define the protoboard and the variables we need. Note that the variable one is automatically defined in the protoboard.

protoboard<FieldT> pb;

pb\_variable<FieldT> out;

pb\_variable<FieldT> x;

pb\_variable<FieldT> sym\_1;

pb\_variable<FieldT> y;

pb\_variable<FieldT> sym\_2;

Next we need to "allocate" the variables on the protoboard. This will associate the variables to a protoboard and will allow us to use the variables to define R1CS constraints.

out.allocate(pb, "out");

x.allocate(pb, "x");

sym\_1.allocate(pb, "sym\_1");

y.allocate(pb, "y");

sym\_2.allocate(pb, "sym\_2");

Note that we are allocating the out variable first. This is because libsnark divides the allocated variables in a protoboard into "primary" (i.e. public) and "auxiliary" (i.e. private) variables. To specify which variables are public and which ones are private we use the protoboard function set\_input\_sizes(n) to specify that the first n variables are public, and the rest are private. In our case we have one public variable out, so we use

pb.set\_input\_sizes(1);

to specify that the variable out should be public, and the rest private.

Next let's add the above R1CS constraints to the protoboard. This is straightforward once we have the variables allocated:

// x\*x = sym\_1

pb.add\_r1cs\_constraint(r1cs\_constraint<FieldT>(x, x, sym\_1));

// sym\_1 \* x = y

pb.add\_r1cs\_constraint(r1cs\_constraint<FieldT>(sym\_1, x, y));

// y + x = sym\_2

pb.add\_r1cs\_constraint(r1cs\_constraint<FieldT>(y + x, 1, sym\_2));

// sym\_2 + 5 = out

pb.add\_r1cs\_constraint(r1cs\_constraint<FieldT>(sym\_2 + 5, 1, out));

Now that we have our circuit in the form of R1CS constraints in the protoboard we can run the Generator and generate proving keys and verification keys for our circuit:

const r1cs\_constraint\_system<FieldT> constraint\_system = pb.get\_constraint\_system();

r1cs\_ppzksnark\_keypair<default\_r1cs\_ppzksnark\_pp> keypair = r1cs\_ppzksnark\_generator<default\_r1cs\_ppzksnark\_pp>(constraint\_system);

Note that the above is the so-called "trusted setup". We can access the proving key through keypair.pk and the verification key through keypair.vk.

Next we want to generate a proof. For this we need to set the values of the public variables in the protoboard, and also set witness values for the private variables:

pb.val(out) = 35;

pb.val(x) = 3;

pb.val(sym\_1) = 9;

pb.val(y) = 27;

pb.val(sym\_2) = 30;

Now that the values are set in the protoboard we can access the public values through pb.primary\_input() and the private values through pb.auxiliary\_input(). Let's use the proving key, the public inputs and the private inputs to create a proof that we know the witness values:

r1cs\_ppzksnark\_proof<default\_r1cs\_ppzksnark\_pp> proof = r1cs\_ppzksnark\_prover<default\_r1cs\_ppzksnark\_pp>(keypair.pk, pb.primary\_input(), pb.auxiliary\_input());

Now that we have a proof we can also verify it, using the previously created proof, the verifying key keypair.vk and the public input pb.primary\_input():

bool verified = r1cs\_ppzksnark\_verifier\_strong\_IC<default\_r1cs\_ppzksnark\_pp>(keypair.vk, pb.primary\_input(), proof);

At this stage the boolean verified should have the value true, given that we put in the correct values for the witness variables.

**libsnark components: 2. Gadgets**

The libsnark library uses *gadgets* to package up R1CS into more manageable pieces and to create cleaner interfaces for developers. They do this by being a wrapper around a protoboard and handling generating R1CS constraints and also generating witness values.

We're going to show how to create a gadget for the example R1CS above in order to make it a bit more manageable.

First we create a new file src/gadget.hpp which contains the gadget file. In our case we want the developer using the gadget to be able to set the public variable out, as well as the private witness variable x, but the gadget itself would take care of the intermediate variables y, sym\_1 and sym\_2.

Thus we create a class test\_gadget, derived from the base gadget class which has the variables y, sym\_1 and sym\_2 as private members (in the C++ sense). The variables x and out will be public class member variables.

In the following sections we go over the functions of this gadget and how to use it.

**Constructor**

As any gadget, the constructor takes as input a protoboard pb. We also have pb\_variable inputs x and out. We assume that the user of the gadget has already allocated x and out to the protoboard.

The constructor then allocates the intermediate variables to the protoboard:

sym\_1.allocate(this->pb, "sym\_1");

y.allocate(this->pb, "y");

sym\_2.allocate(this->pb, "sym\_2");

**Function generate\_r1cs\_constraints()**

This function adds the R1CS constraints corresponding to the circuits. These are the same constraints as we added manually earlier, just bundled up inside this function.

**Function generate\_r1cs\_witness()**

This function assumes that we've already set the public value out, and the witness value x. It then computes the inferred witness values for the intermediate variables sym\_1, y, sym\_2. Thus the user of the gadget never needs to worry about the intermediate variables.

**Using the gadget**

In the file src/test-gadget.cpp we can see how the gadget it used. This file is very similar to the file in the previous section. We start as before by generating curve parameters. After this we initialize the protoboard, and allocate the variables out, x to the protoboard:

protoboard<FieldT> pb;

pb\_variable<FieldT> out;

pb\_variable<FieldT> x;

out.allocate(pb, "out");

x.allocate(pb, "x");

After this we specify which variables are public and which are private (in the zk-SNARK sense). This would be out as the only public variable and the rest as private variables. We also create a new test\_gadget:

pb.set\_input\_sizes(1);

test\_gadget<FieldT> g(pb, out, x);

Next generate the R1CS constraints by simply calling the corresponding function:

g.generate\_r1cs\_constraints();

Now we add the witness values. We add the value 35 for the public variable out and the value 3 for the witness variable x. The rest of the values will be computed inside the gadget:

pb.val(out) = 35;

pb.val(x) = 3;

g.generate\_r1cs\_witness();

That's it! Now we can run the Generator to generate proving and verification keys, create the proof and verify it as we did before.

**Conclusion**

The libsnark zk-SNARK library is a powerful library for defining circuits, generating & verifying proofs, but it can be hard to get a sense of how to use it in practice. This tutorial aims to provide a sense of the high-level components of libsnark and how to use it concretely.

