// Extracts hex-dump vectors from RFC 8439 by line range and prints
// Rust-ready hex string constants. Hex pairs are 2 lowercase (or
// uppercase) hex chars separated by spaces or colons; at most 16 are
// taken per line so a hex-looking ASCII column cannot leak in.
const fs = require('fs');

// RFC 8439 source text; pass the path as argv[1] (defaults to the
// workspace ref copy used during development).
const path =
  process.argv[2] || 'B:/Research/Git Projects Dsh/Deleted_files/refs/rfc8439.txt';
const lines = fs.readFileSync(path, 'utf8').split(/\r?\n/);

const vectors = {
  serialized_block_2_3_2: [577, 580],
  keystream_sunscreen: [736, 741, 'colon'],
  ct_sunscreen: [746, 753],
  otk_2_6_2: [1058, 1059],
  otk_aead_2_8_2: [1308, 1309],
  keystream_aead: [1315, 1323, 'colon'],
  ct_aead_2_8_2: [1325, 1332],
  buffer_aead_2_8_2: [1352, 1361],
  a1_ks1: [1657, 1660],
  a1_ks2: [1688, 1691],
  a1_ks3: [1712, 1715],
  a1_ks4: [1744, 1747],
  a1_ks5: [1768, 1771],
  a2_pt2: [1856, 1879],
  a2_ct2: [1912, 1935],
  a2_pt3: [1950, 1957],
  a2_ct3: [1968, 1975],
  a3_key2_s: [2007, 2007],
  a3_tag3: [2106, 2106],
  a3_tag4: [2153, 2153],
  a3_5_r: [2160, 2160, 'raw'], a3_5_s: [2162, 2162, 'raw'], a3_5_data: [2164, 2164, 'raw'], a3_5_tag: [2166, 2166, 'raw'],
  a3_6_r: [2171, 2171, 'raw'], a3_6_s: [2173, 2173, 'raw'], a3_6_data: [2175, 2175, 'raw'], a3_6_tag: [2177, 2177, 'raw'],
  a3_7_r: [2195, 2195, 'raw'], a3_7_s: [2197, 2197, 'raw'], a3_7_data: [2199, 2201, 'raw'], a3_7_tag: [2203, 2203, 'raw'],
  a3_8_r: [2209, 2209, 'raw'], a3_8_s: [2211, 2211, 'raw'], a3_8_data: [2213, 2215, 'raw'], a3_8_tag: [2217, 2217, 'raw'],
  a3_9_r: [2223, 2223, 'raw'], a3_9_s: [2225, 2225, 'raw'], a3_9_data: [2227, 2227, 'raw'], a3_9_tag: [2229, 2229, 'raw'],
  a3_10_r: [2251, 2251, 'raw'], a3_10_s: [2253, 2253, 'raw'], a3_10_data: [2255, 2258, 'raw'], a3_10_tag: [2260, 2260, 'raw'],
  a3_11_r: [2266, 2266, 'raw'], a3_11_s: [2268, 2268, 'raw'], a3_11_data: [2270, 2272, 'raw'], a3_11_tag: [2274, 2274, 'raw'],
  a4_otk1: [2289, 2290],
  a4_otk2: [2314, 2315],
  a4_otk3: [2328, 2329],
  a5_ct: [2364, 2380],
  a5_otk: [2434, 2435],
  a5_buffer: [2440, 2458],
  a5_pt: [2479, 2495],
};

const re = /^\s*(\d+)\s+((?:[0-9a-fA-F]{2}[\s:])+)/;
const rawRe = /^\s*((?:[0-9a-fA-F]{2}\s+){15}[0-9a-fA-F]{2})\s*$/;
const out = [];
for (const [name, spec] of Object.entries(vectors)) {
  const [s, e, mode = 'dump'] = spec;
  let hex = '';
  for (let i = s - 1; i < e; i++) {
    const line = lines[i];
    if (mode === 'raw') {
      const m = rawRe.exec(line);
      if (!m) { out.push(`// !! ${name}: no raw hex on line ${i + 1}: ${line.slice(0, 60)}`); continue; }
      hex += m[1].trim().split(/\s+/).join(' ') + ' ';
    } else if (mode === 'colon') {
      const pairs = line.match(/[0-9a-fA-F]{2}/g) || [];
      if (pairs.length === 0) { out.push(`// !! ${name}: no colon hex on line ${i + 1}: ${line.slice(0, 60)}`); continue; }
      hex += pairs.join(' ') + ' ';
    } else {
      const m = re.exec(line);
      if (!m) { out.push(`// !! ${name}: no hex on line ${i + 1}: ${line.slice(0, 60)}`); continue; }
      const pairs = m[2].match(/[0-9a-fA-F]{2}/g).slice(0, 16);
      hex += pairs.join(' ') + ' ';
    }
  }
  const bytes = hex.trim() ? hex.trim().split(/\s+/).length : 0;
  out.push(`const ${name.toUpperCase()}: &str = "${hex.trim()}"; // ${bytes} bytes`);
}
// Output: tools/extracted.txt (next to this script).
const outPath = require('path').join(__dirname, 'extracted.txt');
fs.writeFileSync(outPath, out.join('\n') + '\n');
console.log('wrote ' + outPath + ', ' + out.length + ' lines');
