{ mkDerivation, base, bytestring, Cabal, ctrie, data-endian
, network, network-msg, stdenv, transformers
}:
mkDerivation {
  pname = "mDNSResponder-client";
  version = "1.0.3";
  src = ./.;
  libraryHaskellDepends = [
    base bytestring ctrie data-endian network network-msg transformers
  ];
  testHaskellDepends = [ base bytestring Cabal ];
  homepage = "https://github.com/obsidiansystems/mDNSResponder-client";
  description = "Library for talking to the mDNSResponder daemon";
  license = stdenv.lib.licenses.bsd3;
}
