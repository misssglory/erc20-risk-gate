{
  description = "ERC20 risk gate scanner";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;

      packageFor = system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.rustPlatform.buildRustPackage {
          pname = "erc20-risk-gate";
          version = "0.1.0";

          src = ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
          };

          # If build fails asking for cargoHash, either keep cargoLock above,
          # or use cargoHash = pkgs.lib.fakeHash once and replace it with the real hash.
          # cargoHash = pkgs.lib.fakeHash;

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          buildInputs = with pkgs; [
            openssl
          ];

          meta = {
            description = "ERC20 token risk scanner";
            mainProgram = "erc20-risk-gate";
          };
        };
    in
    {
      packages = forAllSystems (system: {
        default = packageFor system;
        erc20-risk-gate = packageFor system;
      });

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/erc20-risk-gate";
        };
      });
    };
}