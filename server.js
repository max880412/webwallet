const express = require('express');
const axios = require('axios');
const app = express();
const PORT = process.env.PORT || 3000;

// Reemplaza con tu clave de API de BscScan
const BSCSCAN_API_KEY = 'YourBscScanApiKey';

app.use(express.static('public'));

// Endpoint para obtener el log de transacciones de una dirección
app.get('/txlog', async (req, res) => {
    const address = req.query.address;
    if (!address) {
        return res.status(400).json({ error: 'No se proporcionó una dirección' });
    }
    
    try {
        const response = await axios.get('https://api.bscscan.com/api', {
            params: {
                module: 'account',
                action: 'txlist',
                address: address,
                startblock: 0,
                endblock: 99999999,
                page: 1,
                offset: 10,
                sort: 'desc',
                apikey: BSCSCAN_API_KEY
            }
        });
        res.json(response.data);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Error al obtener el log de transacciones' });
    }
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
