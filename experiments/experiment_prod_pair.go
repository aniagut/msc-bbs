package experiments

import (
    "fmt"
    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/aniagut/msc-bbs/utils"
    "os"
    "time"
)

// Experiments to compare multiplying pairings using Mul and ProdPair
// MeasurePairingMethods measures the time taken for ProdPair and manual multiplication
func MeasurePairingMethods() {
    file, _ := os.Create("experiments/results/compute_r3_compare_new_v.txt")
    defer file.Close()
    file.WriteString("Pairs,AvgProdPair,AvgManualMul\n")

    pairCounts := []int{2, 3, 5, 10, 20, 50, 100, 200, 500}
    for _, pairCount := range pairCounts {
        var totalProd, totalMul time.Duration

        // prepare random bases and scalars
        g1s := make([]*e.G1, pairCount)
        g2s := make([]*e.G2, pairCount)
        scalars := make([]*e.Scalar, pairCount)
        for i := range g1s {
            g1s[i] = e.G1Generator()
            g2s[i] = e.G2Generator()
            r, _ := utils.RandomScalar()
            scalars[i] = &r
        }

        // repeat 10× for stability
        for t := 0; t < 10; t++ {
            // --- ProdPair timing ---
            start := time.Now()
            _ = e.ProdPair(g1s, g2s, scalars)
            totalProd += time.Since(start)

            // --- manual Mul timing ---
            start = time.Now()
            // first pairing
            tmp := new(e.G1)
            tmp.ScalarMult(scalars[0], g1s[0])
            acc := e.Pair(tmp, g2s[0])
            // accumulate the rest
            for i := 1; i < pairCount; i++ {
                tmp.ScalarMult(scalars[i], g1s[i])
                p := e.Pair(tmp, g2s[i])
                acc.Mul(acc, p)
            }
            totalMul += time.Since(start)
        }

        avgProd := totalProd / 10
        avgMul := totalMul / 10
        fmt.Printf("%4d pairs → ProdPair: %v, Manual Mul: %v\n", pairCount, avgProd, avgMul)
        file.WriteString(fmt.Sprintf("%d,%v,%v\n", pairCount, avgProd, avgMul))
    }
}