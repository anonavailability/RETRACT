# RETRACT
Prototype code for the paper Expressive Designated Verifier Anonymous Credentials

## Running the prototype

Assuming you have [Docker](https://docker.com/), it is easy to work with the prototype.

To build run:

    docker build -t retract .

To start an interactive session inside the created container run:

    docker run -it --rm --volume="$(pwd)"/:/app/retract/ retract

Then enter the shared folder:

    cd retract

Execute all tests:

    python3 -m pytest --no-header -v -s

Or execute a specific test:

    python3 -m pytest --no-header -v -s -k "test_designated_verifier_poseidon_trapdoor"
    python3 -m pytest --no-header -v -s -k "test_bbsplus"
    python3 -m pytest --no-header -v -s -k "test_raw_prototype_holder_proof"
    python3 -m pytest --no-header -v -s -k "test_raw_prototype_designated_verifier_proof"

Note. To build additional circuits, look at [xjsnark](https://github.com/akosba/xjsnark). 

--------------------------------------------------------------------------------
Disclaimer
--------------------------------------------------------------------------------

This is an early release that could contain issues and inconsistencies. The implementations provided in this repository are currently only research prototypes.

