import {createOneKeyLinuxNobleAdapter} from '../../sdk/onekey-linux-noble-adapter.mjs';
export const nativeBleAdapterApproved=true;
export async function openNativeBleAdapter() {
 const imported=await import('@stoprocent/noble');
 return createOneKeyLinuxNobleAdapter({noble:imported.default??imported});
}
