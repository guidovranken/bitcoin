all: fuzzer-base58 \
	fuzzer-bloom \
	fuzzer-pubkey \
	fuzzer-median \
	fuzzer-blockchain-load \
	fuzzer-hash \
	fuzzer-deserialize \
	fuzzer-script-1 \
	fuzzer-script-2 \
	fuzzer-utilstr \
	fuzzer-uint256 \
	fuzzer-merkleblock \

fuzzer-base58: fuzzer-base58.o
	clang++11-with-options.sh -o fuzzer-base58 -lpthread fuzzer-base58.o ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/secp256k1/.libs/libsecp256k1.a ../src/.libs/libbitcoinconsensus.a ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent libFuzzer.a

fuzzer-bloom: fuzzer-bloom.o
	clang++11-with-options.sh -o fuzzer-bloom -lpthread fuzzer-bloom.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/secp256k1/.libs/libsecp256k1.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent libFuzzer.a

fuzzer-pubkey: fuzzer-pubkey.o
	clang++11-with-options.sh -o fuzzer-pubkey -lpthread fuzzer-pubkey.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/secp256k1/.libs/libsecp256k1.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent libFuzzer.a

fuzzer-median: fuzzer-median.o
	clang++11-with-options.sh -o fuzzer-median -lpthread fuzzer-median.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/secp256k1/.libs/libsecp256k1.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent libFuzzer.a

fuzzer-blockchain-load: fuzzer-blockchain-load.o
	clang++11-with-options.sh -o fuzzer-blockchain-load -lpthread fuzzer-blockchain-load.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/secp256k1/.libs/libsecp256k1.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a ../src/leveldb/libmemenv.a ../src/leveldb/libleveldb.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto -levent_pthreads -levent libFuzzer.a -ldl

fuzzer-hash: fuzzer-hash.o
	clang++11-with-options.sh -o fuzzer-hash -lpthread fuzzer-hash.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/secp256k1/.libs/libsecp256k1.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent libFuzzer.a

fuzzer-deserialize: fuzzer-deserialize.o
	clang++11-with-options.sh -o fuzzer-deserialize -lpthread fuzzer-deserialize.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/.libs/libbitcoinconsensus.a  ../src/secp256k1/.libs/libsecp256k1.a ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent libFuzzer.a

fuzzer-script-1: fuzzer-script-1.o
	clang++11-with-options.sh -o fuzzer-script-1 -lpthread fuzzer-script-1.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent ../src/secp256k1/.libs/libsecp256k1.a libFuzzer.a

fuzzer-script-2: fuzzer-script-2.o
	clang++11-with-options.sh -o fuzzer-script-2 -lpthread fuzzer-script-2.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent ../src/secp256k1/.libs/libsecp256k1.a libFuzzer.a

fuzzer-utilstr: fuzzer-utilstr.o
	clang++11-with-options.sh -o fuzzer-utilstr -lpthread fuzzer-utilstr.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent ../src/secp256k1/.libs/libsecp256k1.a libFuzzer.a

fuzzer-uint256: fuzzer-uint256.o
	clang++11-with-options.sh -o fuzzer-uint256 -lpthread fuzzer-uint256.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent ../src/secp256k1/.libs/libsecp256k1.a libFuzzer.a

fuzzer-merkleblock: fuzzer-merkleblock.o
	clang++11-with-options.sh -o fuzzer-merkleblock -lpthread fuzzer-merkleblock.o ../src/libbitcoin_server.a ../src/libbitcoin_common.a ../src/libbitcoin_cli.a ../src/univalue/.libs/libunivalue.a ../src/.libs/libbitcoinconsensus.a  ../src/libbitcoin_util.a ../src/crypto/libbitcoin_crypto.a -L/usr/lib/x86_64-linux-gnu -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono -lssl -lcrypto  -lcrypto  -levent ../src/secp256k1/.libs/libsecp256k1.a libFuzzer.a

fuzzer-base58.o: fuzzer-base58.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include fuzzer-base58.cpp

fuzzer-bloom.o: fuzzer-bloom.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include fuzzer-bloom.cpp

fuzzer-pubkey.o: fuzzer-pubkey.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-pubkey.cpp

fuzzer-median.o: fuzzer-median.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-median.cpp

fuzzer-blockchain-load.o: fuzzer-blockchain-load.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-blockchain-load.cpp

fuzzer-hash.o: fuzzer-hash.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-hash.cpp

fuzzer-deserialize.o: fuzzer-deserialize.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-deserialize.cpp

fuzzer-script-1.o: fuzzer-script-1.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-script-1.cpp

fuzzer-script-2.o: fuzzer-script-2.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-script-2.cpp

fuzzer-utilstr.o: fuzzer-utilstr.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-utilstr.cpp

fuzzer-uint256.o: fuzzer-uint256.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-uint256.cpp

fuzzer-merkleblock.o: fuzzer-merkleblock.cpp
	clang++11-with-options.sh -c -I../src -I../src/univalue/include -I../src/leveldb/include -I ../src/secp256k1/include/ fuzzer-merkleblock.cpp

clean:
	rm fuzzer-base58 fuzzer-base58.o \
		fuzzer-bloom fuzzer-bloom.o \
		fuzzer-pubkey fuzzer-pubkey.o \
		fuzzer-median fuzzer-median.o \
		fuzzer-blockchain-load fuzzer-blockchain-load.o \
		fuzzer-hash fuzzer-hash.o \
		fuzzer-deserialize fuzzer-deserialize.o \
		fuzzer-script-1 fuzzer-script-1.o \
		fuzzer-script-2 fuzzer-script-2.o \
		fuzzer-net fuzzer-net.o \
		fuzzer-utilstr fuzzer-utilstr.o \
		fuzzer-uint256 fuzzer-uint256.o \
		fuzzer-merkleblock fuzzer-merkleblock.o \
