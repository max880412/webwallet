// Variables globales
let wallet;
let provider;
let signer;
const usdtContractAddress = "0x55d398326f99059fF775485246999027B3197955";
// ABI mínima para balanceOf y transfer
const usdtAbi = [
    "function balanceOf(address) view returns (uint256)",
    "function transfer(address to, uint256 amount) returns (bool)"
];

document.getElementById("createWalletBtn").addEventListener("click", async () => {
    // Crear un provider para conectarse a BSC Mainnet
    provider = new ethers.providers.JsonRpcProvider("https://bsc-dataseed.binance.org/");
    
    // Crear una nueva wallet aleatoria
    wallet = ethers.Wallet.createRandom();
    // Conectar la wallet al provider
    signer = wallet.connect(provider);
    
    // Mostrar información de la wallet
    document.getElementById("walletAddress").innerText = wallet.address;
    document.getElementById("walletPrivateKey").innerText = wallet.privateKey;
    document.getElementById("walletInfo").style.display = "block";
    
    // Actualizar el balance y el log de transacciones de inmediato y cada 30 segundos
    updateBalance();
    updateTxLog();
    setInterval(updateBalance, 30000);
    setInterval(updateTxLog, 30000);
});

async function updateBalance() {
    try {
        const contract = new ethers.Contract(usdtContractAddress, usdtAbi, provider);
        const balance = await contract.balanceOf(wallet.address);
        // Convertir el balance de wei a unidades legibles (asumido 18 decimales)
        const formattedBalance = ethers.utils.formatUnits(balance, 18);
        document.getElementById("walletBalance").innerText = formattedBalance;
    } catch (err) {
        console.error("Error al obtener balance:", err);
    }
}

async function updateTxLog() {
    if (!wallet) return;
    try {
        const response = await fetch(`/txlog?address=${wallet.address}`);
        const data = await response.json();
        const txLogDiv = document.getElementById("txLog");
        if (data.status === "1" && data.result.length > 0) {
            txLogDiv.innerHTML = data.result.map(tx => {
                return `<div>
                    <p><strong>Hash:</strong> ${tx.hash}</p>
                    <p><strong>Desde:</strong> ${tx.from} <strong>Para:</strong> ${tx.to}</p>
                    <p><strong>Valor:</strong> ${ethers.utils.formatUnits(tx.value, 18)} USDT</p>
                    <hr>
                </div>`;
            }).join("");
        } else {
            txLogDiv.innerHTML = "<p>No hay transacciones recientes.</p>";
        }
    } catch (err) {
        console.error("Error al obtener el log de transacciones:", err);
    }
}

document.getElementById("sendTxBtn").addEventListener("click", async () => {
    const toAddress = document.getElementById("toAddress").value.trim();
    const amount = document.getElementById("amount").value;
    
    if (!ethers.utils.isAddress(toAddress)) {
        alert("Dirección de destino inválida.");
        return;
    }
    
    if (!amount || amount <= 0) {
        alert("La cantidad debe ser mayor a 0.");
        return;
    }
    
    try {
        const contract = new ethers.Contract(usdtContractAddress, usdtAbi, signer);
        // Convertir la cantidad a wei (18 decimales)
        const amountWei = ethers.utils.parseUnits(amount, 18);
        const txResponse = await contract.transfer(toAddress, amountWei);
        alert("Transacción enviada. Hash: " + txResponse.hash);
        // Espera a que la transacción se confirme y actualiza balance y log
        await txResponse.wait();
        updateBalance();
        updateTxLog();
    } catch (err) {
        console.error("Error al enviar transacción:", err);
        alert("Error al enviar la transacción.");
    }
});
