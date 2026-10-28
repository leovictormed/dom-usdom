#!/usr/bin/env node
import {materializeOneKeyIosOwnerIdentitiesV2} from '../sdk/onekey-ios-owner-identities-v2.mjs';if(process.argv.length!==6)throw new Error('usage: materialize-onekey-ios-owner-identities-v2 OWNER1 OWNER2 OWNER3 OUTPUT');await materializeOneKeyIosOwnerIdentitiesV2({evidencePaths:process.argv.slice(2,5),outputPath:process.argv[5]});
