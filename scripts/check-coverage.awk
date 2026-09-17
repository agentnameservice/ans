# Count each source block once across cross-package coverage profiles.
NR == 1 { next }
{
    split($1, location, ":")
    file[$1] = location[1]
    statements[$1] = $2
    if ($3 > 0) hit[$1] = 1
}
END {
    for (block in statements) {
        if (file[block] !~ /\/internal\//) continue
        total += statements[block]
        covered += statements[block] * hit[block]
        if (file[block] ~ /\/internal\/domain\//) {
            domain_total += statements[block]
            domain_covered += statements[block] * hit[block]
        }
        if (file[block] ~ /\/internal\/crypto\//) {
            crypto_total += statements[block]
            crypto_covered += statements[block] * hit[block]
        }
    }
    if (total == 0 || domain_total == 0 || crypto_total == 0) {
        print "FAIL: coverage profile is missing required internal packages"
        exit 1
    }
    printf "Coverage: internal %.2f%%, domain %.2f%%, crypto %.2f%%\n", \
        100 * covered / total, 100 * domain_covered / domain_total, \
        100 * crypto_covered / crypto_total
    if (100 * covered < minimum * total || domain_covered != domain_total || \
        100 * crypto_covered < 95 * crypto_total) {
        printf "FAIL: require internal >= %s%%, domain = 100%%, crypto >= 95%%\n", minimum
        exit 1
    }
    print "Coverage thresholds passed."
}
