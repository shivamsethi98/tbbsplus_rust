import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import "@nomicfoundation/hardhat-foundry";
import * as dotenv from "dotenv";

dotenv.config();

const INFURA_KEY = process.env.INFURA_KEY || "c9bc72c05c7746e59893a52424e9e478";

const FORK_URL = process.env.FORK_URL || `https://mainnet.infura.io/v3/${INFURA_KEY}`;

const config: HardhatUserConfig = {
  solidity: "0.8.24",
  networks: {
    hardhat: {
      forking: {
        url: FORK_URL,
        // blockNumber: 20400000, // optionally pin a block for reproducibility
      },
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
