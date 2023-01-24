// @ts-ignore
import { ethers } from 'hardhat'
import { expect } from 'chai'
import {
    hash4,
    SparseMerkleTree,
    genRandomSalt,
    hash3,
    hash6,
    stringifyBigInts,
} from '@unirep/utils'
import {
    AGGREGATE_KEY_COUNT,
    Circuit,
    EPOCH_TREE_DEPTH,
    EPOCH_TREE_ARITY,
    defaultEpochTreeLeaf,
    AggregateEpochKeysProof,
    SNARK_FIELD_SIZE,
} from '@unirep/circuits'

import { EPOCH_LENGTH } from '../src'
import { deployUnirep } from '../deploy'

import { defaultProver } from '@unirep/circuits/provers/defaultProver'

function genAggregateEpochKeysCircuitInputs(
    epoch,
    attester,
    hashchainIndex,
    hashchain,
    epochTree?
) {
    const tree =
        epochTree ??
        new SparseMerkleTree(
            EPOCH_TREE_DEPTH,
            defaultEpochTreeLeaf,
            EPOCH_TREE_ARITY
        )
    const startRoot = tree.root
    const dummyEpochKeys = Array(
        AGGREGATE_KEY_COUNT - hashchain.epochKeys.length
    )
        .fill(null)
        .map(() => '0x0000000')
    const dummyBalances = Array(
        AGGREGATE_KEY_COUNT - hashchain.epochKeyBalances.length
    )
        .fill(null)
        .map(() => [0, 0, 0, 0])
    const allEpochKeys = [hashchain.epochKeys, dummyEpochKeys].flat()
    const allBalances = [
        hashchain.epochKeyBalances.map(
            ({ posRep, negRep, graffiti, timestamp }) => {
                return [
                    posRep.toString(),
                    negRep.toString(),
                    graffiti.toString(),
                    timestamp.toString(),
                ]
            }
        ),
        dummyBalances,
    ].flat()
    const circuitInputs = {
        start_root: startRoot,
        epoch_keys: allEpochKeys.map((k) => k.toString()),
        epoch_key_balances: allBalances,
        old_epoch_key_hashes:
            Array(AGGREGATE_KEY_COUNT).fill(defaultEpochTreeLeaf),
        path_elements: allEpochKeys.map((key, i) => {
            const p = tree.createProof(BigInt(key))
            if (i < hashchain.epochKeys.length) {
                const { posRep, negRep, graffiti, timestamp } =
                    hashchain.epochKeyBalances[i]
                tree.update(
                    BigInt(key),
                    hash4([posRep, negRep, graffiti, timestamp])
                )
            }
            return p
        }),
        epoch: epoch.toString(),
        attester_id: attester.address,
        hashchain_index: hashchainIndex.toString(),
        epoch_key_count: hashchain.epochKeys.length, // process epoch keys with attestations
    }

    return stringifyBigInts(circuitInputs)
}

describe('Attestations', function () {
    this.timeout(120000)
    let unirepContract
    let snapshot

    before(async () => {
        const accounts = await ethers.getSigners()
        unirepContract = await deployUnirep(accounts[0])

        const attester = accounts[1]
        await unirepContract
            .connect(attester)
            .attesterSignUp(EPOCH_LENGTH)
            .then((t) => t.wait())
    })

    beforeEach(async () => {
        snapshot = await ethers.provider.send('evm_snapshot', [])
    })

    afterEach(async () => {
        await ethers.provider.send('evm_revert', [snapshot])
    })

    it('should fail to submit attestation with wrong epoch', async () => {
        const accounts = await ethers.getSigners()
        const attester = accounts[1]
        const wrongEpoch = 444444
        const epochKey = BigInt(24910)
        await expect(
            unirepContract
                .connect(attester)
                .submitAttestation(wrongEpoch, epochKey, 1, 1, 0)
        ).to.be.revertedWithCustomError(unirepContract, 'EpochNotMatch')
    })

    it('should fail to submit attestation with invalid epoch key', async () => {
        const accounts = await ethers.getSigners()
        const attester = accounts[1]
        const epoch = 0
        await expect(
            unirepContract
                .connect(attester)
                .submitAttestation(epoch, SNARK_FIELD_SIZE, 1, 1, 0)
        ).to.be.revertedWithCustomError(unirepContract, 'InvalidEpochKey')
    })

    it('should fail to submit attestation after epoch ends', async () => {
        const accounts = await ethers.getSigners()
        const attester = accounts[1]
        const oldEpoch = await unirepContract.attesterCurrentEpoch(
            attester.address
        )
        const epochKey = BigInt(24910)

        // epoch transition
        await ethers.provider.send('evm_increaseTime', [EPOCH_LENGTH])
        await ethers.provider.send('evm_mine', [])
        const newEpoch = await unirepContract.attesterCurrentEpoch(
            attester.address
        )
        expect(oldEpoch.toString()).not.equal(newEpoch.toString())

        await expect(
            unirepContract
                .connect(attester)
                .submitAttestation(oldEpoch, epochKey, 1, 1, 0)
        ).to.be.revertedWithCustomError(unirepContract, 'EpochNotMatch')
    })

    it('should fail to submit from non-attester', async () => {
        const accounts = await ethers.getSigners()
        const attester = accounts[1]
        const wrongAttester = accounts[5]
        const epoch = await unirepContract.attesterCurrentEpoch(
            attester.address
        )
        const epochKey = BigInt(24910)

        await expect(
            unirepContract
                .connect(wrongAttester)
                .submitAttestation(epoch, epochKey, 1, 1, 0)
        ).to.be.revertedWithCustomError(unirepContract, 'AttesterNotSignUp')
    })

    it('should submit attestation with graffiti', async () => {
        const accounts = await ethers.getSigners()
        const attester = accounts[1]
        const epoch = await unirepContract.attesterCurrentEpoch(
            attester.address
        )
        const epochKey = BigInt(24910)
        const posRep = 1
        const negRep = 5
        const graffiti = 101910
        const tx = await unirepContract
            .connect(attester)
            .submitAttestation(epoch, epochKey, posRep, negRep, graffiti)
        const { timestamp } = await tx
            .wait()
            .then(({ blockNumber }) => ethers.provider.getBlock(blockNumber))

        expect(tx)
            .to.emit(unirepContract, 'AttestationSubmitted')
            .withArgs(
                epoch,
                epochKey,
                attester.address,
                posRep,
                negRep,
                graffiti,
                timestamp
            )
    })

    it('should submit attestation without graffiti', async () => {
        const accounts = await ethers.getSigners()
        const attester = accounts[1]

        const epoch = await unirepContract.attesterCurrentEpoch(
            attester.address
        )
        const epochKey = BigInt(24910)
        const posRep = 1
        const negRep = 5
        const graffiti = 0
        const timestamp = 0

        const tx = await unirepContract
            .connect(attester)
            .submitAttestation(epoch, epochKey, posRep, negRep, graffiti)
        await tx.wait()

        expect(tx)
            .to.emit(unirepContract, 'AttestationSubmitted')
            .withArgs(
                epoch,
                epochKey,
                attester.address,
                posRep,
                negRep,
                graffiti,
                timestamp
            )
    })
})
