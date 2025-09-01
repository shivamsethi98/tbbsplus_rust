import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-foundry";
import * as dotenv from "dotenv";

dotenv.config();

const INFURA_KEY = process.env.INFURA_KEY;

const FORK_URL = process.env.FORK_URL || `https://mainnet.infura.io/v3/${INFURA_KEY}`;
const SHOULD_FORK = process.env.FORK === "1";

const config: HardhatUserConfig = {
  defaultNetwork: process.env.HARDHAT_NETWORK || "localhost",
  solidity: {
    version: "0.8.27",
    settings: {
  optimizer: { enabled: true, runs: 200 },
  viaIR: true,
  evmVersion: "prague",
    },
  },
  paths: {
    sources: "contracts",
    tests: "test",
  },
  networks: {
    hardhat: {
      ...(SHOULD_FORK
        ? {
            forking: {
              url: FORK_URL,
              // blockNumber: 20400000, // optionally pin a block for reproducibility
            },
          }
        : {}),
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
    anvil: {
      url: "http://127.0.0.1:8545",
      chainId: 31337,
    },
    sepolia: {
      url: `https://sepolia.infura.io/v3/${INFURA_KEY}`,
    },
    hoodi: {
      // Provide HOODI_URL in env, else fallback to FORK_URL
      url: process.env.HOODI_URL || FORK_URL,
    },
    mainnet: {
      url: `https://mainnet.infura.io/v3/${INFURA_KEY}`,
    },
  },
};

export default config;
