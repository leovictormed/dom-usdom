#!/usr/bin/env node
import {buildReownProjectRequest} from '../sdk/onekey-ios-onboarding.mjs';process.stdout.write(`${JSON.stringify(buildReownProjectRequest(),null,2)}\n`);
