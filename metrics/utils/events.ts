import { Contract } from 'ethers';

export async function waitForEvent(contract: Contract, filter: any, timeoutMs = 30000): Promise<any> {
  return new Promise((resolve, reject) => {
    const handler = (...args: any[]) => {
      clearTimeout(timer);
      try { (contract as any).off(filter, handler); } catch {}
      resolve(args);
    };
    const timer = setTimeout(() => {
      try { (contract as any).off(filter, handler); } catch {}
      reject(new Error('waitForEvent timeout'));
    }, timeoutMs);
    (contract as any).on(filter, handler);
  });
}

export async function waitForSingleEvent(contract: Contract, filter: any, timeoutMs = 30000): Promise<any> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('waitForSingleEvent timeout'));
    }, timeoutMs);
    (contract as any).once(filter, (...args: any[]) => {
      clearTimeout(timer);
      resolve(args);
    });
  });
}


