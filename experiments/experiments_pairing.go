package experiments

import (
    "fmt"
    "os"
    "time"
    e "github.com/cloudflare/circl/ecc/bls12381"
    "github.com/aniagut/msc-bbs/utils"
)

func MeasurePairingTime() {
    // Open the results file for writing
    file, err := os.Create("experiments/results/pairing_time_old_results.txt")
    if err != nil {
        fmt.Printf("Error creating results file: %v\n", err)
        return
    }
    defer file.Close()
    // Write the header to the file
    _, err = file.WriteString("PairingCount,AveragePairingTime\n")
    if err != nil {
        fmt.Printf("Error writing to results file: %v\n", err)
        return
    }
    // Define the number of pairings to test
    pairingCounts := []int{10, 20, 50, 100, 500, 1000, 2000, 5000, 10000}
    // Generate random scalars for pairing
    rX, err := utils.RandomScalar()
    if err != nil {
        fmt.Printf("Error generating random scalar: %v\n", err)
        return
    }
    // Generate G1 and G2 generators
    g1 := e.G1Generator()
    g2 := e.G2Generator()

    for _, pairingCount := range pairingCounts {
        var totalTime time.Duration
        // Run pairing computations 10 times and measure the total time
        for i := 0; i < 10; i++ {
            start := time.Now()
            // Compute pairing e(T3_rX, g2) for the specified number of pairings
            for j := 0; j < pairingCount; j++ {
                pair1 := e.Pair(g1, g2)
                pair1Exp := new(e.Gt)
                pair1Exp.Exp(pair1, &rX)
            }
            // Measure the elapsed time
            elapsed := time.Since(start)
            totalTime += elapsed
        }
        // Calculate the average time
        averageTime := totalTime / 10
        // Print the results
        fmt.Printf("Average pairing time for %d pairings: %v\n", pairingCount, averageTime)
        // Write the results to the file
        _, err = file.WriteString(fmt.Sprintf("%d,%v\n", pairingCount, averageTime))
        if err != nil {
            fmt.Printf("Error writing to results file: %v\n", err)
            return
        }
    }
}