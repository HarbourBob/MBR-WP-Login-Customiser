<?php
/**
 * Minimal self-contained QR Code encoder.
 *
 * Byte mode, error-correction level M, automatic version selection up to
 * version 10 (ample for otpauth:// URIs). No dependencies, no external calls.
 * Produces a boolean module matrix and an inline SVG.
 *
 * @package MBR_Login_Customiser
 */

if (!defined('ABSPATH')) {
    exit;
}

class MBR_QR {

    private static $exp = array();
    private static $log = array();

    // EC level M characteristics per version (1-10):
    // [ec_per_block, [ [num_blocks, data_per_block], ... ] ]
    private static $ecM = array(
        1  => array(10, array(array(1, 16))),
        2  => array(16, array(array(1, 28))),
        3  => array(26, array(array(1, 44))),
        4  => array(18, array(array(2, 32))),
        5  => array(24, array(array(2, 43))),
        6  => array(16, array(array(4, 27))),
        7  => array(18, array(array(4, 31))),
        8  => array(22, array(array(2, 38), array(2, 39))),
        9  => array(22, array(array(3, 36), array(2, 37))),
        10 => array(26, array(array(4, 43), array(1, 44))),
    );

    // Alignment-pattern centre coordinates per version.
    private static $align = array(
        1 => array(), 2 => array(6, 18), 3 => array(6, 22), 4 => array(6, 26),
        5 => array(6, 30), 6 => array(6, 34), 7 => array(6, 22, 38),
        8 => array(6, 24, 42), 9 => array(6, 26, 46), 10 => array(6, 28, 50),
    );

    // Remainder bits per version (1-10).
    private static $remainder = array(1 => 0, 2 => 7, 3 => 7, 4 => 7, 5 => 7, 6 => 7, 7 => 0, 8 => 0, 9 => 0, 10 => 0);

    /* ---- Galois field ---- */

    private static function init_gf() {
        if (self::$exp) {
            return;
        }
        $x = 1;
        for ($i = 0; $i < 256; $i++) {
            self::$exp[$i] = $x;
            $x <<= 1;
            if ($x & 0x100) {
                $x ^= 0x11d;
            }
        }
        for ($i = 0; $i < 255; $i++) {
            self::$log[self::$exp[$i]] = $i;
        }
    }

    private static function gmul($a, $b) {
        if ($a == 0 || $b == 0) {
            return 0;
        }
        return self::$exp[(self::$log[$a] + self::$log[$b]) % 255];
    }

    private static function rs_generator($deg) {
        $g = array(1); // index = degree
        for ($i = 0; $i < $deg; $i++) {
            $alpha = self::$exp[$i];
            $new = array_fill(0, count($g) + 1, 0);
            for ($d = 0; $d < count($g); $d++) {
                $new[$d + 1] ^= $g[$d];
                $new[$d] ^= self::gmul($g[$d], $alpha);
            }
            $g = $new;
        }
        return $g;
    }

    private static function rs_encode($data, $ecLen) {
        $gen = array_reverse(self::rs_generator($ecLen)); // highest degree first, monic
        $res = array_merge($data, array_fill(0, $ecLen, 0));
        $n = count($data);
        for ($i = 0; $i < $n; $i++) {
            $coef = $res[$i];
            if ($coef != 0) {
                for ($j = 0; $j < count($gen); $j++) {
                    $res[$i + $j] ^= self::gmul($gen[$j], $coef);
                }
            }
        }
        return array_slice($res, $n, $ecLen);
    }

    /* ---- version selection + bitstream ---- */

    private static function choose_version($len) {
        for ($v = 1; $v <= 10; $v++) {
            $data_codewords = 0;
            foreach (self::$ecM[$v][1] as $grp) {
                $data_codewords += $grp[0] * $grp[1];
            }
            $count_bits = ($v <= 9) ? 8 : 16;
            $needed = 4 + $count_bits + 8 * $len;
            if ($needed <= $data_codewords * 8) {
                return $v;
            }
        }
        return 0; // too long
    }

    private static function build_codewords($text, $version) {
        $len = strlen($text);
        $count_bits = ($version <= 9) ? 8 : 16;

        // Bit string.
        $bits = '0100'; // byte mode
        $bits .= str_pad(decbin($len), $count_bits, '0', STR_PAD_LEFT);
        for ($i = 0; $i < $len; $i++) {
            $bits .= str_pad(decbin(ord($text[$i])), 8, '0', STR_PAD_LEFT);
        }

        $data_codewords = 0;
        foreach (self::$ecM[$version][1] as $grp) {
            $data_codewords += $grp[0] * $grp[1];
        }
        $capacity_bits = $data_codewords * 8;

        // Terminator (up to 4 zero bits).
        $term = min(4, $capacity_bits - strlen($bits));
        $bits .= str_repeat('0', max(0, $term));

        // Pad to byte boundary.
        if (strlen($bits) % 8 !== 0) {
            $bits .= str_repeat('0', 8 - (strlen($bits) % 8));
        }

        // Codeword array.
        $codewords = array();
        for ($i = 0; $i < strlen($bits); $i += 8) {
            $codewords[] = bindec(substr($bits, $i, 8));
        }

        // Pad bytes.
        $pad = array(0xEC, 0x11);
        $pi = 0;
        while (count($codewords) < $data_codewords) {
            $codewords[] = $pad[$pi % 2];
            $pi++;
        }

        // Split into blocks, RS-encode, interleave.
        $ecLen = self::$ecM[$version][0];
        $blocks = array();
        $ecblocks = array();
        $offset = 0;
        foreach (self::$ecM[$version][1] as $grp) {
            for ($b = 0; $b < $grp[0]; $b++) {
                $blk = array_slice($codewords, $offset, $grp[1]);
                $offset += $grp[1];
                $blocks[] = $blk;
                $ecblocks[] = self::rs_encode($blk, $ecLen);
            }
        }

        $max_data = 0;
        foreach ($blocks as $b) {
            $max_data = max($max_data, count($b));
        }

        $final = array();
        for ($i = 0; $i < $max_data; $i++) {
            foreach ($blocks as $b) {
                if ($i < count($b)) {
                    $final[] = $b[$i];
                }
            }
        }
        for ($i = 0; $i < $ecLen; $i++) {
            foreach ($ecblocks as $b) {
                $final[] = $b[$i];
            }
        }

        // To bit string + remainder bits.
        $out = '';
        foreach ($final as $cw) {
            $out .= str_pad(decbin($cw), 8, '0', STR_PAD_LEFT);
        }
        $out .= str_repeat('0', self::$remainder[$version]);
        return $out;
    }

    /* ---- matrix construction ---- */

    public static function get_matrix($text) {
        self::init_gf();
        $version = self::choose_version(strlen($text));
        if (0 === $version) {
            return null;
        }
        $size = 17 + 4 * $version;

        $m = array();   // module value (0/1) or null
        $f = array();   // is-function module
        for ($r = 0; $r < $size; $r++) {
            $m[$r] = array_fill(0, $size, null);
            $f[$r] = array_fill(0, $size, false);
        }

        $set = function ($r, $c, $val) use (&$m, &$f) {
            $m[$r][$c] = $val ? 1 : 0;
            $f[$r][$c] = true;
        };

        // Finder patterns + separators.
        $finder = function ($r0, $c0) use (&$set, $size) {
            for ($r = -1; $r <= 7; $r++) {
                for ($c = -1; $c <= 7; $c++) {
                    $rr = $r0 + $r; $cc = $c0 + $c;
                    if ($rr < 0 || $rr >= $size || $cc < 0 || $cc >= $size) {
                        continue;
                    }
                    $in = ($r >= 0 && $r <= 6 && $c >= 0 && $c <= 6);
                    $dark = $in && (
                        $r == 0 || $r == 6 || $c == 0 || $c == 6 ||
                        ($r >= 2 && $r <= 4 && $c >= 2 && $c <= 4)
                    );
                    $set($rr, $cc, $dark ? 1 : 0);
                }
            }
        };
        $finder(0, 0);
        $finder(0, $size - 7);
        $finder($size - 7, 0);

        // Timing patterns.
        for ($i = 8; $i < $size - 8; $i++) {
            $set(6, $i, ($i % 2 == 0) ? 1 : 0);
            $set($i, 6, ($i % 2 == 0) ? 1 : 0);
        }

        // Alignment patterns.
        $centres = self::$align[$version];
        foreach ($centres as $ar) {
            foreach ($centres as $ac) {
                // Skip those overlapping finder areas.
                if (($ar <= 8 && $ac <= 8) || ($ar <= 8 && $ac >= $size - 9) || ($ar >= $size - 9 && $ac <= 8)) {
                    continue;
                }
                for ($r = -2; $r <= 2; $r++) {
                    for ($c = -2; $c <= 2; $c++) {
                        $dark = (abs($r) == 2 || abs($c) == 2 || ($r == 0 && $c == 0)) ? 1 : 0;
                        $set($ar + $r, $ac + $c, $dark);
                    }
                }
            }
        }

        // Dark module.
        $set($size - 8, 8, 1);

        // Reserve format-info areas (mark function; values set later).
        $reserve = function ($r, $c) use (&$f, &$m) {
            if ($m[$r][$c] === null) {
                $f[$r][$c] = true;
                $m[$r][$c] = 0;
            }
        };
        for ($i = 0; $i < 9; $i++) {
            $reserve(8, $i);
            $reserve($i, 8);
        }
        for ($i = 0; $i < 8; $i++) {
            $reserve(8, $size - 1 - $i);
            $reserve($size - 1 - $i, 8);
        }

        // Reserve version-info areas (v7+).
        if ($version >= 7) {
            for ($i = 0; $i < 6; $i++) {
                for ($j = 0; $j < 3; $j++) {
                    $reserve($size - 11 + $j, $i);
                    $reserve($i, $size - 11 + $j);
                }
            }
        }

        // Place data bits in zigzag.
        $bits = self::build_codewords($text, $version);
        $bi = 0;
        $blen = strlen($bits);
        $up = true;
        for ($col = $size - 1; $col > 0; $col -= 2) {
            if ($col == 6) {
                $col = 5; // skip vertical timing column
            }
            for ($i = 0; $i < $size; $i++) {
                $row = $up ? ($size - 1 - $i) : $i;
                for ($cc = 0; $cc < 2; $cc++) {
                    $c = $col - $cc;
                    if (!$f[$row][$c]) {
                        $bit = ($bi < $blen) ? (int) $bits[$bi] : 0;
                        $bi++;
                        $m[$row][$c] = $bit;
                    }
                }
            }
            $up = !$up;
        }

        // Choose best mask.
        $best = null; $best_pen = PHP_INT_MAX; $best_mask = 0;
        for ($mask = 0; $mask < 8; $mask++) {
            $cand = self::apply_mask($m, $f, $size, $mask);
            self::place_format($cand, $f, $size, $mask);
            if ($version >= 7) {
                self::place_version($cand, $size, $version);
            }
            $pen = self::penalty($cand, $size);
            if ($pen < $best_pen) {
                $best_pen = $pen;
                $best = $cand;
                $best_mask = $mask;
            }
        }
        return $best;
    }

    private static function apply_mask($m, $f, $size, $mask) {
        $out = $m;
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if ($f[$r][$c]) {
                    continue;
                }
                $flip = false;
                switch ($mask) {
                    case 0: $flip = (($r + $c) % 2 == 0); break;
                    case 1: $flip = ($r % 2 == 0); break;
                    case 2: $flip = ($c % 3 == 0); break;
                    case 3: $flip = (($r + $c) % 3 == 0); break;
                    case 4: $flip = ((intdiv($r, 2) + intdiv($c, 3)) % 2 == 0); break;
                    case 5: $flip = ((($r * $c) % 2) + (($r * $c) % 3) == 0); break;
                    case 6: $flip = (((($r * $c) % 2) + (($r * $c) % 3)) % 2 == 0); break;
                    case 7: $flip = (((($r + $c) % 2) + (($r * $c) % 3)) % 2 == 0); break;
                }
                $out[$r][$c] = $flip ? ($m[$r][$c] ^ 1) : $m[$r][$c];
            }
        }
        return $out;
    }

    private static function place_format(&$m, $f, $size, $mask) {
        $ec = 0; // level M = 00
        $data = ($ec << 3) | $mask; // 5 bits
        $rem = $data;
        for ($i = 0; $i < 10; $i++) {
            $rem = ($rem << 1) ^ ((($rem >> 9) & 1) ? 0x537 : 0);
        }
        $fmt = (($data << 10) | $rem) ^ 0x5412; // 15 bits

        $bitsArr = array();
        for ($i = 14; $i >= 0; $i--) {
            $bitsArr[] = ($fmt >> $i) & 1;
        }

        // Around top-left finder.
        $coords1 = array(
            array(8, 0), array(8, 1), array(8, 2), array(8, 3), array(8, 4), array(8, 5),
            array(8, 7), array(8, 8), array(7, 8), array(5, 8), array(4, 8), array(3, 8),
            array(2, 8), array(1, 8), array(0, 8),
        );
        foreach ($coords1 as $i => $rc) {
            $m[$rc[0]][$rc[1]] = $bitsArr[$i];
        }

        // Split across the other two finders.
        $coords2 = array(
            array($size - 1, 8), array($size - 2, 8), array($size - 3, 8), array($size - 4, 8),
            array($size - 5, 8), array($size - 6, 8), array($size - 7, 8),
            array(8, $size - 8), array(8, $size - 7), array(8, $size - 6), array(8, $size - 5),
            array(8, $size - 4), array(8, $size - 3), array(8, $size - 2), array(8, $size - 1),
        );
        foreach ($coords2 as $i => $rc) {
            $m[$rc[0]][$rc[1]] = $bitsArr[$i];
        }
    }

    private static function place_version(&$m, $size, $version) {
        $rem = $version;
        for ($i = 0; $i < 12; $i++) {
            $rem = ($rem << 1) ^ ((($rem >> 11) & 1) ? 0x1f25 : 0);
        }
        $vbits = ($version << 12) | $rem; // 18 bits

        for ($i = 0; $i < 18; $i++) {
            $bit = ($vbits >> $i) & 1;
            $r = intdiv($i, 3);
            $c = $i % 3;
            $m[$r][$size - 11 + $c] = $bit;
            $m[$size - 11 + $c][$r] = $bit;
        }
    }

    private static function penalty($m, $size) {
        $p = 0;
        // Rule 1: runs of 5+ same colour.
        for ($r = 0; $r < $size; $r++) {
            $run = 1;
            for ($c = 1; $c < $size; $c++) {
                if ($m[$r][$c] === $m[$r][$c - 1]) {
                    $run++;
                } else {
                    if ($run >= 5) { $p += 3 + ($run - 5); }
                    $run = 1;
                }
            }
            if ($run >= 5) { $p += 3 + ($run - 5); }
        }
        for ($c = 0; $c < $size; $c++) {
            $run = 1;
            for ($r = 1; $r < $size; $r++) {
                if ($m[$r][$c] === $m[$r - 1][$c]) {
                    $run++;
                } else {
                    if ($run >= 5) { $p += 3 + ($run - 5); }
                    $run = 1;
                }
            }
            if ($run >= 5) { $p += 3 + ($run - 5); }
        }
        // Rule 2: 2x2 blocks.
        for ($r = 0; $r < $size - 1; $r++) {
            for ($c = 0; $c < $size - 1; $c++) {
                $v = $m[$r][$c];
                if ($v === $m[$r][$c + 1] && $v === $m[$r + 1][$c] && $v === $m[$r + 1][$c + 1]) {
                    $p += 3;
                }
            }
        }
        // Rule 3: finder-like patterns.
        $patA = array(1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0);
        $patB = array(0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1);
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size - 10; $c++) {
                $okA = true; $okB = true;
                for ($k = 0; $k < 11; $k++) {
                    if ($m[$r][$c + $k] !== $patA[$k]) { $okA = false; }
                    if ($m[$r][$c + $k] !== $patB[$k]) { $okB = false; }
                }
                if ($okA || $okB) { $p += 40; }
            }
        }
        for ($c = 0; $c < $size; $c++) {
            for ($r = 0; $r < $size - 10; $r++) {
                $okA = true; $okB = true;
                for ($k = 0; $k < 11; $k++) {
                    if ($m[$r + $k][$c] !== $patA[$k]) { $okA = false; }
                    if ($m[$r + $k][$c] !== $patB[$k]) { $okB = false; }
                }
                if ($okA || $okB) { $p += 40; }
            }
        }
        // Rule 4: dark proportion.
        $dark = 0;
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if ($m[$r][$c]) { $dark++; }
            }
        }
        $ratio = $dark * 100 / ($size * $size);
        $p += 10 * (int) (abs($ratio - 50) / 5);
        return $p;
    }

    /* ---- output ---- */

    public static function to_svg($text, $module = 6, $quiet = 4) {
        $m = self::get_matrix($text);
        if (null === $m) {
            return '';
        }
        $size = count($m);
        $dim = ($size + 2 * $quiet) * $module;
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' . $dim . '" height="' . $dim
            . '" viewBox="0 0 ' . $dim . ' ' . $dim . '" role="img">';
        $svg .= '<rect width="' . $dim . '" height="' . $dim . '" fill="#ffffff"/>';
        $svg .= '<path fill="#000000" d="';
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if ($m[$r][$c]) {
                    $x = ($c + $quiet) * $module;
                    $y = ($r + $quiet) * $module;
                    $svg .= 'M' . $x . ' ' . $y . 'h' . $module . 'v' . $module . 'h-' . $module . 'z';
                }
            }
        }
        $svg .= '"/></svg>';
        return $svg;
    }
}
