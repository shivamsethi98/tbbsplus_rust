import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-foundry";
import * as dotenv from "dotenv";

dotenv.config();

const INFURA_KEY = process.env.INFURA_KEY || "c9bc72c05c7746e59893a52424e9e478";

const FORK_URL = process.env.FORK_URL || `https://mainnet.infura.io/v3/${INFURA_KEY}`;
const SHOULD_FORK = process.env.FORK === "1";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
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
