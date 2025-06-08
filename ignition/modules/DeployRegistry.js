// ignition/modules/DeployRegistry.js

const { buildModule } = require("@nomicfoundation/hardhat-ignition/modules");

// --- Configuration ---
// IMPORTANT: Replace with your actual MetaMask wallet address before running.
const PARTNER_WALLET_ADDRESS = "0x1668dA9a3e992a8b8fD9A701768D0Aac493AF6E6";

// The fee is set to 0.01 ETH.
// We pass this as a string to the module, as Hardhat Ignition handles the conversion.
const PARTNER_FEE_WEI = "10000000000000000"; // This is 0.01 ETH in wei

module.exports = buildModule("SecureCertificateRegistryModule", (m) => {
  // Get the constructor arguments from the constants defined above.
  const partnerWallet = m.getParameter("_partner", PARTNER_WALLET_ADDRESS);
  const partnerFee = m.getParameter("_fee", PARTNER_FEE_WEI);

  // Define the deployment of the SecureCertificateRegistry contract.
  const registry = m.contract("SecureCertificateRegistry", [partnerWallet, partnerFee]);

  // Return the deployed contract instance, which makes its address available.
  return { registry };
});