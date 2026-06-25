(function () {
  const form = document.getElementById('calc-form');
  const errorEl = document.getElementById('error');
  const resultEl = document.getElementById('result');
  const resultBody = document.getElementById('result-body');
  const binaryView = document.getElementById('binary-view');
  const subnetsEl = document.getElementById('subnets');
  const subnetsInfo = document.getElementById('subnets-info');
  const subnetsBody = document.getElementById('subnets-body');

  const MAX_SUBNETS_SHOWN = 1024;

  function isValidIp(ip) {
    const parts = ip.trim().split('.');
    if (parts.length !== 4) return false;
    return parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
  }

  function ipToInt(ip) {
    return ip.trim().split('.').reduce((acc, octet) => (acc << 8) + Number(octet), 0) >>> 0;
  }

  function intToIp(n) {
    n = n >>> 0;
    return [24, 16, 8, 0].map((shift) => (n >>> shift) & 255).join('.');
  }

  function maskFromCidr(bits) {
    if (bits === 0) return 0;
    return (0xffffffff << (32 - bits)) >>> 0;
  }

  function isContiguousMask(maskInt) {
    let seenZero = false;
    for (let i = 31; i >= 0; i--) {
      const bit = (maskInt >>> i) & 1;
      if (bit === 0) seenZero = true;
      else if (seenZero) return false;
    }
    return true;
  }

  function cidrFromMaskInt(maskInt) {
    let bits = 0;
    for (let i = 31; i >= 0; i--) {
      if ((maskInt >>> i) & 1) bits++;
      else break;
    }
    return bits;
  }

  // Accepts "/24", "24", or "255.255.255.0" -> returns { bits, maskInt } or throws
  function parseMask(input) {
    const raw = input.trim();
    if (raw === '') return null;
    if (raw.includes('.')) {
      if (!isValidIp(raw)) throw new Error(`Geçersiz netmask: ${raw}`);
      const maskInt = ipToInt(raw);
      if (!isContiguousMask(maskInt)) throw new Error(`Netmask bitleri ardışık olmalı: ${raw}`);
      return { bits: cidrFromMaskInt(maskInt), maskInt };
    }
    const cidrStr = raw.replace(/^\//, '');
    if (!/^\d{1,2}$/.test(cidrStr)) throw new Error(`Geçersiz netmask: ${input}`);
    const bits = Number(cidrStr);
    if (bits < 0 || bits > 32) throw new Error(`CIDR 0-32 arasında olmalı: ${input}`);
    return { bits, maskInt: maskFromCidr(bits) };
  }

  function toBinaryOctets(n) {
    return intToIp(n).split('.').map((o) => Number(o).toString(2).padStart(8, '0'));
  }

  function isPrivate(ipInt) {
    const ranges = [
      [ipToInt('10.0.0.0'), ipToInt('10.255.255.255')],
      [ipToInt('172.16.0.0'), ipToInt('172.31.255.255')],
      [ipToInt('192.168.0.0'), ipToInt('192.168.255.255')],
      [ipToInt('127.0.0.0'), ipToInt('127.255.255.255')],
      [ipToInt('169.254.0.0'), ipToInt('169.254.255.255')],
    ];
    return ranges.some(([lo, hi]) => ipInt >= lo && ipInt <= hi);
  }

  function ipClass(ipInt) {
    const first = (ipInt >>> 24) & 255;
    if (first < 128) return 'A';
    if (first < 192) return 'B';
    if (first < 224) return 'C';
    if (first < 240) return 'D (Multicast)';
    return 'E (Reserved)';
  }

  function row(label, value, mono = true) {
    const tr = document.createElement('tr');
    const td1 = document.createElement('td');
    td1.textContent = label;
    const td2 = document.createElement('td');
    if (mono) td2.classList.add('mono');
    td2.textContent = value;
    tr.appendChild(td1);
    tr.appendChild(td2);
    return tr;
  }

  function renderBinaryRow(label, octets, splitBit) {
    const wrap = document.createElement('div');
    wrap.className = 'binary-row';
    const lab = document.createElement('span');
    lab.className = 'label';
    lab.textContent = label;
    wrap.appendChild(lab);

    let bitIndex = 0;
    octets.forEach((octet, oi) => {
      [...octet].forEach((bit) => {
        const span = document.createElement('span');
        span.className = bitIndex < splitBit ? 'bit-net' : 'bit-host';
        span.textContent = bit;
        wrap.appendChild(span);
        bitIndex++;
      });
      if (oi < octets.length - 1) {
        const sep = document.createElement('span');
        sep.className = 'bit-sep';
        sep.textContent = '.';
        wrap.appendChild(sep);
      }
    });
    return wrap;
  }

  function computeNetwork(ipInt, bits) {
    const maskInt = maskFromCidr(bits);
    const network = (ipInt & maskInt) >>> 0;
    const broadcast = bits === 32 ? network : (network | (~maskInt >>> 0)) >>> 0;
    const wildcard = (~maskInt) >>> 0;
    const totalHosts = Math.pow(2, 32 - bits);
    let hostMin, hostMax, usableHosts;
    if (bits >= 31) {
      hostMin = network;
      hostMax = broadcast;
      usableHosts = totalHosts;
    } else {
      hostMin = (network + 1) >>> 0;
      hostMax = (broadcast - 1) >>> 0;
      usableHosts = totalHosts - 2;
    }
    return { maskInt, network, broadcast, wildcard, totalHosts, usableHosts, hostMin, hostMax };
  }

  function showError(msg) {
    errorEl.textContent = msg;
    errorEl.hidden = false;
    resultEl.hidden = true;
    subnetsEl.hidden = true;
  }

  function clearError() {
    errorEl.hidden = true;
  }

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    clearError();

    const hostStr = document.getElementById('host').value;
    const mask1Str = document.getElementById('mask1').value;
    const mask2Str = document.getElementById('mask2').value;

    try {
      if (!isValidIp(hostStr)) throw new Error(`Geçersiz IP adresi: ${hostStr}`);
      const ipInt = ipToInt(hostStr);

      const m1 = parseMask(mask1Str);
      if (!m1) throw new Error('Netmask zorunludur.');

      const info = computeNetwork(ipInt, m1.bits);

      resultBody.innerHTML = '';
      resultBody.appendChild(row('Host IP', intToIp(ipInt)));
      resultBody.appendChild(row('Netmask', `${intToIp(info.maskInt)} = /${m1.bits}`));
      resultBody.appendChild(row('Wildcard', intToIp(info.wildcard)));
      resultBody.appendChild(row('Network', `${intToIp(info.network)}/${m1.bits}`));
      resultBody.appendChild(row('Broadcast', intToIp(info.broadcast)));
      resultBody.appendChild(row('Host Aralığı', `${intToIp(info.hostMin)} - ${intToIp(info.hostMax)}`));
      resultBody.appendChild(row('Kullanılabilir Host', info.usableHosts.toLocaleString('tr-TR'), false));
      resultBody.appendChild(row('Toplam Adres', info.totalHosts.toLocaleString('tr-TR'), false));
      resultBody.appendChild(row('IP Sınıfı', ipClass(ipInt), false));
      resultBody.appendChild(row('Tip', isPrivate(ipInt) ? 'Özel (Private)' : 'Genel (Public)', false));

      binaryView.innerHTML = '';
      binaryView.appendChild(renderBinaryRow('Host:', toBinaryOctets(ipInt), m1.bits));
      binaryView.appendChild(renderBinaryRow('Netmask:', toBinaryOctets(info.maskInt), m1.bits));
      binaryView.appendChild(renderBinaryRow('Network:', toBinaryOctets(info.network), m1.bits));
      binaryView.appendChild(renderBinaryRow('Broadcast:', toBinaryOctets(info.broadcast), m1.bits));

      resultEl.hidden = false;

      const m2 = parseMask(mask2Str);
      if (m2 && m2.bits > m1.bits) {
        const subnetCount = Math.pow(2, m2.bits - m1.bits);
        const subnetSize = Math.pow(2, 32 - m2.bits);
        const shown = Math.min(subnetCount, MAX_SUBNETS_SHOWN);

        subnetsInfo.textContent = subnetCount > MAX_SUBNETS_SHOWN
          ? `${subnetCount.toLocaleString('tr-TR')} alt ağ bulundu, ilk ${MAX_SUBNETS_SHOWN} gösteriliyor.`
          : `${subnetCount.toLocaleString('tr-TR')} alt ağ /${m2.bits} olarak bölündü.`;

        subnetsBody.innerHTML = '';
        for (let i = 0; i < shown; i++) {
          const subNetworkInt = (info.network + i * subnetSize) >>> 0;
          const sub = computeNetwork(subNetworkInt, m2.bits);
          const tr = document.createElement('tr');
          [
            String(i + 1),
            `${intToIp(sub.network)}/${m2.bits}`,
            intToIp(sub.maskInt),
            `${intToIp(sub.hostMin)} - ${intToIp(sub.hostMax)}`,
            intToIp(sub.broadcast),
          ].forEach((text) => {
            const td = document.createElement('td');
            td.classList.add('mono');
            td.textContent = text;
            tr.appendChild(td);
          });
          subnetsBody.appendChild(tr);
        }
        subnetsEl.hidden = false;
      } else if (m2 && m2.bits <= m1.bits) {
        subnetsEl.hidden = true;
        throw new Error('İkinci netmask, ilk netmaskten daha uzun (daha büyük) olmalı.');
      } else {
        subnetsEl.hidden = true;
      }
    } catch (err) {
      showError(err.message);
    }
  });

  // Prefill from query string, e.g. ?host=217.177.0.0&mask1=29&mask2=
  function prefillFromQuery() {
    const params = new URLSearchParams(window.location.search);
    if (params.has('host')) document.getElementById('host').value = params.get('host');
    if (params.has('mask1')) document.getElementById('mask1').value = params.get('mask1');
    if (params.has('mask2')) document.getElementById('mask2').value = params.get('mask2');
    if (params.has('host') && params.has('mask1')) {
      form.dispatchEvent(new Event('submit', { cancelable: true }));
    }
  }

  prefillFromQuery();
})();
