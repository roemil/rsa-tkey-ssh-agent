# RSA SSH AGENT
This is a proof of concept to use the Tkey SSH Agent with RSA keys. It uses a specific RSA signer, with 2048 bits key and SHA512. It is based on the SSH agent written by Tilltis: https://github.com/tillitis/tkey-ssh-agent

Due to hardware limitations, the tkey will read a private rsa key and load it into the hardware. The signing will be done by Tkey.

In the near future the Tkey will consume the private key and store an encrypted key on the host.

For more information, see https://tillitis.se/

## Usage
* Generate RSA key: ssh-keygen -t rsa-sha2-512 -b 2048 -m PEM (no passphrase support yet)
* start the agent: ./tkey-ssh-agent --port /path/to/device -a /path/to/agent.sock --rsa-key-path /path/to/your/private/key

## Compiling from source
* Make sure you have built the RSA signer:https://github.com/roemil/rsa-signer, copy the bin to signer/
* Build the SSH agent: make clean && make

## Limitations
* The hardware is unfortunately not optimized for division which the RSA algorithm use a lot, so key generation is slow. Hence we generate keys on the host computer. This makes the Tkey less portable, however, generating keys with Tkey takes more then 1 hour as of now.

## License
This project is based https://github.com/tillitis/tkey-ssh-agent. 
This repo is licensed to "GNU General Public License v2.0 only". See [LICENSE](https://github.com/roemil/rsa-tkey-ssh-agent/blob/main/LICENSE) for full license text.

### TODO
* Encrypt the private rsa file with tkey and store on laptop
* Allow rsa keys to be generated with passphrase.
* Fix the build script :)