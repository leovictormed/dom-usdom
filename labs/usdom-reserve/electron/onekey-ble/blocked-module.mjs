const denied=()=>{throw new Error('forbidden transport or network module is unavailable in the OneKey BLE renderer');};
export default new Proxy(denied,{get:denied,apply:denied,construct:denied});
export const get=denied,post=denied,request=denied,create=denied;
