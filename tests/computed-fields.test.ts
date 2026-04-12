import {
  ComputedFieldRegistry,
  applyComputedFields,
  applyComputedFieldsToResponse,
  UNISWAP_V2_PAIR_FIELDS,
  UNISWAP_V2_TOKEN_FIELDS,
  UNISWAP_V2_AGGREGATION_FIELDS,
  GENERIC_AMM_PAIR_FIELDS,
  LENDING_PROTOCOL_FIELDS,
  LP_SHARE_FIELDS,
  ComputedFieldSet,
} from '../src/computed-fields';
import { QueryResponse } from '../src/types';

describe('ComputedFieldRegistry', () => {
  let registry: ComputedFieldRegistry;

  beforeEach(() => {
    registry = new ComputedFieldRegistry();
  });

  it('should register and retrieve computed fields', () => {
    const fields: ComputedFieldSet = [
      {
        name: 'testField',
        description: 'Test field',
        dependencies: ['a', 'b'],
        compute: (record) => record.a + record.b,
      },
    ];

    registry.register('dataset1', fields);

    expect(registry.has('dataset1')).toBe(true);
    expect(registry.get('dataset1')).toBe(fields);
  });

  it('should return undefined for unregistered dataset', () => {
    expect(registry.get('unknown')).toBeUndefined();
    expect(registry.has('unknown')).toBe(false);
  });

  it('should unregister computed fields', () => {
    const fields: ComputedFieldSet = [
      {
        name: 'testField',
        description: 'Test field',
        dependencies: ['a'],
        compute: (record) => record.a * 2,
      },
    ];

    registry.register('dataset1', fields);
    expect(registry.has('dataset1')).toBe(true);

    const result = registry.unregister('dataset1');
    expect(result).toBe(true);
    expect(registry.has('dataset1')).toBe(false);
  });

  it('should clear all registered fields', () => {
    registry.register('dataset1', []);
    registry.register('dataset2', []);

    registry.clear();

    expect(registry.has('dataset1')).toBe(false);
    expect(registry.has('dataset2')).toBe(false);
  });
});

describe('applyComputedFields', () => {
  it('should compute fields from record data', () => {
    const fields: ComputedFieldSet = [
      {
        name: 'sum',
        description: 'Sum of a and b',
        dependencies: ['a', 'b'],
        compute: (record) => record.a + record.b,
      },
    ];

    const record = { a: 10, b: 20 };
    const result = applyComputedFields(record, fields);

    expect(result.a).toBe(10);
    expect(result.b).toBe(20);
    expect(result.sum).toBe(30);
  });

  it('should not modify original record', () => {
    const fields: ComputedFieldSet = [
      {
        name: 'doubled',
        description: 'Double of x',
        dependencies: ['x'],
        compute: (record) => record.x * 2,
      },
    ];

    const record = { x: 5 };
    const result = applyComputedFields(record, fields);

    expect(result.doubled).toBe(10);
    expect(record).toEqual({ x: 5 }); // Original unchanged
  });

  it('should skip fields with missing dependencies', () => {
    const fields: ComputedFieldSet = [
      {
        name: 'ratio',
        description: 'Ratio a/b',
        dependencies: ['a', 'b'],
        compute: (record) => record.a / record.b,
      },
    ];

    const record = { a: 10 }; // Missing 'b'
    const result = applyComputedFields(record, fields);

    expect(result.a).toBe(10);
    expect(result.ratio).toBeUndefined();
  });

  it('should skip fields when compute returns undefined', () => {
    const fields: ComputedFieldSet = [
      {
        name: 'safeDivide',
        description: 'Safe division',
        dependencies: ['a', 'b'],
        compute: (record) => (record.b === 0 ? undefined : record.a / record.b),
      },
    ];

    const record = { a: 10, b: 0 };
    const result = applyComputedFields(record, fields);

    expect(result.safeDivide).toBeUndefined();
  });

  it('should handle multiple computed fields', () => {
    const fields: ComputedFieldSet = [
      {
        name: 'sum',
        description: 'Sum',
        dependencies: ['a', 'b'],
        compute: (record) => record.a + record.b,
      },
      {
        name: 'product',
        description: 'Product',
        dependencies: ['a', 'b'],
        compute: (record) => record.a * record.b,
      },
      {
        name: 'diff',
        description: 'Difference',
        dependencies: ['a', 'b'],
        compute: (record) => record.a - record.b,
      },
    ];

    const record = { a: 10, b: 3 };
    const result = applyComputedFields(record, fields);

    expect(result.sum).toBe(13);
    expect(result.product).toBe(30);
    expect(result.diff).toBe(7);
  });
});

describe('applyComputedFieldsToResponse', () => {
  it('should apply computed fields to all documents', () => {
    const fields: ComputedFieldSet = [
      {
        name: 'price',
        description: 'Price ratio',
        dependencies: ['reserve0', 'reserve1'],
        compute: (record) =>
          record.reserve0 === 0 ? undefined : record.reserve1 / record.reserve0,
      },
    ];

    const response: QueryResponse = {
      documents: [
        { id: '1', reserve0: 100, reserve1: 200 },
        { id: '2', reserve0: 50, reserve1: 150 },
        { id: '3', reserve0: 0, reserve1: 100 }, // Division by zero case
      ],
      total: 3,
    };

    const result = applyComputedFieldsToResponse(response, fields);

    expect(result.documents[0].price).toBe(2);
    expect(result.documents[1].price).toBe(3);
    expect(result.documents[2].price).toBeUndefined();
    expect(result.total).toBe(3);
  });

  it('should preserve other response properties', () => {
    const fields: ComputedFieldSet = [];

    const response: QueryResponse = {
      documents: [{ id: '1' }],
      total: 1,
      offset: 0,
      limit: 10,
      proof: 'some-proof',
      verifiedRootHash: '0xabc',
    };

    const result = applyComputedFieldsToResponse(response, fields);

    expect(result.total).toBe(1);
    expect(result.offset).toBe(0);
    expect(result.limit).toBe(10);
    expect(result.proof).toBe('some-proof');
    expect(result.verifiedRootHash).toBe('0xabc');
  });
});

describe('UNISWAP_V2_PAIR_FIELDS', () => {
  it('should compute token0Price from reserves', () => {
    const record = { reserve0: 1000, reserve1: 2000 };
    const result = applyComputedFields(record, UNISWAP_V2_PAIR_FIELDS);

    expect(result.token0Price).toBe(2); // 2000 / 1000
  });

  it('should compute token1Price from reserves', () => {
    const record = { reserve0: 1000, reserve1: 2000 };
    const result = applyComputedFields(record, UNISWAP_V2_PAIR_FIELDS);

    expect(result.token1Price).toBe(0.5); // 1000 / 2000
  });

  it('should handle string reserves', () => {
    const record = { reserve0: '1000000000000000000', reserve1: '2000000000000000000' };
    const result = applyComputedFields(record, UNISWAP_V2_PAIR_FIELDS);

    expect(result.token0Price).toBe(2);
    expect(result.token1Price).toBe(0.5);
  });

  it('should handle hex reserves', () => {
    const record = { reserve0: '0x64', reserve1: '0xc8' }; // 100, 200
    const result = applyComputedFields(record, UNISWAP_V2_PAIR_FIELDS);

    expect(result.token0Price).toBe(2);
    expect(result.token1Price).toBe(0.5);
  });

  it('should return undefined for division by zero', () => {
    const record = { reserve0: 0, reserve1: 1000 };
    const result = applyComputedFields(record, UNISWAP_V2_PAIR_FIELDS);

    expect(result.token0Price).toBeUndefined();
    expect(result.token1Price).toBe(0); // 0 / 1000 = 0, which is valid
  });

  it('should adjust for token decimals', () => {
    // Token0 has 6 decimals (USDC), Token1 has 18 decimals (ETH)
    const record = {
      reserve0: 1000000, // 1 USDC (6 decimals)
      reserve1: 1000000000000000000, // 1 ETH (18 decimals)
      token0: { decimals: 6 },
      token1: { decimals: 18 },
    };
    const result = applyComputedFields(record, UNISWAP_V2_PAIR_FIELDS);

    // token0Price = (reserve1 / reserve0) * 10^(decimals0 - decimals1)
    // = (1e18 / 1e6) * 10^(6-18) = 1e12 * 1e-12 = 1
    expect(result.token0Price).toBeCloseTo(1, 10);
  });
});

describe('UNISWAP_V2_TOKEN_FIELDS', () => {
  it('should return 1 for WETH', () => {
    const record = { symbol: 'WETH' };
    const result = applyComputedFields(record, UNISWAP_V2_TOKEN_FIELDS);

    expect(result.derivedETH).toBe(1.0);
  });

  it('should compute derivedETH when token0 is WETH', () => {
    const record = {
      ethPairReserve0: 1000, // WETH
      ethPairReserve1: 2000, // This token
      ethPairToken0IsWeth: true,
    };
    const result = applyComputedFields(record, UNISWAP_V2_TOKEN_FIELDS);

    expect(result.derivedETH).toBe(0.5); // 1000 / 2000
  });

  it('should compute derivedETH when token1 is WETH', () => {
    const record = {
      ethPairReserve0: 2000, // This token
      ethPairReserve1: 1000, // WETH
      ethPairToken0IsWeth: false,
    };
    const result = applyComputedFields(record, UNISWAP_V2_TOKEN_FIELDS);

    expect(result.derivedETH).toBe(0.5); // 1000 / 2000
  });
});

describe('UNISWAP_V2_AGGREGATION_FIELDS', () => {
  it('should compute dailyVolumeUSD', () => {
    const record = {
      dailyVolumeETH: 100,
      ethPriceUSD: 2000,
    };
    const result = applyComputedFields(record, UNISWAP_V2_AGGREGATION_FIELDS);

    expect(result.dailyVolumeUSD).toBe(200000);
  });

  it('should compute totalLiquidityUSD', () => {
    const record = {
      totalLiquidityETH: 500,
      ethPriceUSD: 2000,
    };
    const result = applyComputedFields(record, UNISWAP_V2_AGGREGATION_FIELDS);

    expect(result.totalLiquidityUSD).toBe(1000000);
  });
});

describe('GENERIC_AMM_PAIR_FIELDS', () => {
  it('should compute prices without decimal adjustment', () => {
    const record = { reserve0: 100, reserve1: 300 };
    const result = applyComputedFields(record, GENERIC_AMM_PAIR_FIELDS);

    expect(result.token0Price).toBe(3);
    expect(result.token1Price).toBeCloseTo(0.333, 2);
  });
});

describe('LENDING_PROTOCOL_FIELDS', () => {
  it('should compute utilizationRate', () => {
    const record = {
      totalBorrows: 800,
      totalSupply: 1000,
    };
    const result = applyComputedFields(record, LENDING_PROTOCOL_FIELDS);

    expect(result.utilizationRate).toBe(0.8);
  });

  it('should compute availableLiquidity', () => {
    const record = {
      totalBorrows: 800,
      totalSupply: 1000,
    };
    const result = applyComputedFields(record, LENDING_PROTOCOL_FIELDS);

    expect(result.availableLiquidity).toBe(200);
  });

  it('should handle zero supply', () => {
    const record = {
      totalBorrows: 0,
      totalSupply: 0,
    };
    const result = applyComputedFields(record, LENDING_PROTOCOL_FIELDS);

    expect(result.utilizationRate).toBeUndefined(); // Division by zero
  });
});

describe('LP_SHARE_FIELDS', () => {
  it('should compute shareOfPool', () => {
    const record = {
      userLPBalance: 100,
      totalLPSupply: 1000,
    };
    const result = applyComputedFields(record, LP_SHARE_FIELDS);

    expect(result.shareOfPool).toBe(0.1);
  });

  it('should compute userToken0Amount and userToken1Amount', () => {
    const record = {
      userLPBalance: 100,
      totalLPSupply: 1000,
      reserve0: 10000,
      reserve1: 20000,
    };
    const result = applyComputedFields(record, LP_SHARE_FIELDS);

    expect(result.userToken0Amount).toBe(1000); // 10% of 10000
    expect(result.userToken1Amount).toBe(2000); // 10% of 20000
  });
});

describe('Integration: Uniswap V2 drop-in replacement', () => {
  it('should produce The Graph-compatible query response', () => {
    // Simulate a query response from Willow with proven reserve data
    const willowResponse: QueryResponse = {
      documents: [
        {
          id: '0xb4e16d0168e52d35cacd2c6185b44281ec28c9dc', // USDC-WETH
          reserve0: '50000000000', // 50,000 USDC (6 decimals)
          reserve1: '25000000000000000000', // 25 ETH (18 decimals)
          token0: { symbol: 'USDC', decimals: 6 },
          token1: { symbol: 'WETH', decimals: 18 },
        },
      ],
      total: 1,
      verifiedRootHash: '0xabc123',
    };

    // Apply Uniswap V2 computed fields
    const result = applyComputedFieldsToResponse(willowResponse, UNISWAP_V2_PAIR_FIELDS);

    // Verify the response matches what The Graph would return
    const pair = result.documents[0];

    // Original proven data preserved
    expect(pair.reserve0).toBe('50000000000');
    expect(pair.reserve1).toBe('25000000000000000000');

    // Computed prices added
    expect(pair.token0Price).toBeDefined();
    expect(pair.token1Price).toBeDefined();

    // token0Price = (reserve1 / reserve0) * 10^(decimals0 - decimals1)
    // = (25e18 / 50e9) * 10^(6-18)
    // = 5e8 * 1e-12 = 0.0005
    // This means 1 USDC = 0.0005 ETH
    expect(pair.token0Price).toBeCloseTo(0.0005, 6);

    // token1Price = (reserve0 / reserve1) * 10^(decimals1 - decimals0)
    // = (50e9 / 25e18) * 10^(18-6)
    // = 2e-9 * 1e12 = 2000
    // This means 1 ETH = 2000 USDC
    expect(pair.token1Price).toBeCloseTo(2000, 0);

    // Verification data preserved
    expect(result.verifiedRootHash).toBe('0xabc123');
  });

  it('should handle multiple pairs in batch query', () => {
    const response: QueryResponse = {
      documents: [
        { id: 'pair1', reserve0: 1000, reserve1: 2000 },
        { id: 'pair2', reserve0: 500, reserve1: 1500 },
        { id: 'pair3', reserve0: 100, reserve1: 400 },
      ],
      total: 3,
    };

    const result = applyComputedFieldsToResponse(response, GENERIC_AMM_PAIR_FIELDS);

    expect(result.documents[0].token0Price).toBe(2);
    expect(result.documents[1].token0Price).toBe(3);
    expect(result.documents[2].token0Price).toBe(4);
  });
});
