import {describe,expect,it} from "vitest";
import {extraMessages,messages,modalMessages,setupMessages,translationKeys} from "./i18n";
describe("translations",()=>{it("keeps Thai and English keys in sync",()=>{expect(translationKeys(messages["th-TH"])).toEqual(translationKeys(messages["en-US"]));expect(translationKeys(extraMessages["th-TH"])).toEqual(translationKeys(extraMessages["en-US"]));expect(translationKeys(modalMessages["th-TH"])).toEqual(translationKeys(modalMessages["en-US"]));expect(translationKeys(setupMessages["th-TH"])).toEqual(translationKeys(setupMessages["en-US"]))})});
