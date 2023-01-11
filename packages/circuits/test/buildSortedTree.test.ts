import { expect } from 'chai'
import { IncrementalMerkleTree } from '@unirep/utils'
import { CHANGE_TREE_DEPTH, CHANGE_TREE_ARITY } from '../config'
import { genProofAndVerify } from './utils'
import { Circuit } from '../src'

describe('Build sorted merkle tree', function () {
    this.timeout(300000)
    it('should build a tree', async () => {
        const leaves = Array(CHANGE_TREE_ARITY ** CHANGE_TREE_DEPTH)
            .fill(null)
            .map(() => BigInt(Math.floor(Math.random() * 1000000000000)))
        const sortedLeaves = [...leaves].sort((a, b) => (a > b ? 1 : -1))
        const indexes = sortedLeaves.map((l) => leaves.indexOf(l))
        console.log(indexes)
        const tree = new IncrementalMerkleTree(
            CHANGE_TREE_DEPTH,
            0,
            CHANGE_TREE_ARITY
        )
        for (const leaf of sortedLeaves) {
            tree.insert(BigInt(leaf))
        }
        const circuitInputs = {
            sorted_leaves: sortedLeaves,
            leaf_degree: indexes,
        }
        const { isValid, publicSignals } = await genProofAndVerify(
            Circuit.buildSortedTree,
            circuitInputs
        )
        console.log(JSON.stringify(publicSignals))
        console.log(tree.root)
    })
})
