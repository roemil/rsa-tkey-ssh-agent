# RSA SSH AGENT
This is a proof of concept to use the Tkey SSH Agent with RSA keys. It uses a specific RSA signer, with 2048 bits key and SHA512. It is based on the SSH agent written by Tilltis.

For more information, see https://tillitis.se/

## Usage
* Build the SSH agent: make clean && make
* start the agent: ./rsa-tkey-ssh-agent --port /path/to/device -a /path/to/agent.sock
* In another terminal, generate a new RSA keypair: ssh-add -L
* Add the public key (shown in the terminal) to the server you want to authenticate against
* Touch the tkey when prompted (ie when you are signing a message for authentication)

## Limitations
* The hardware is unfortunately not optimized for division which the RSA algorithm use a lot, so key generation is slow.
* A new keypair is generated each time the Tkey is power cycled, meaning you need to upload the public key to the server each time a new pair is generated. This is a huge drawback in terms of usability but unfortuntanly the RSA algorithm is random and there is no persistant storage in Tkey. It works fast with the QEMU emulator though: https://github.com/tillitis/tkey-devtools