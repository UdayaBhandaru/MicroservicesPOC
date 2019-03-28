import {NgModule} from "@angular/core";
import { HttpModule } from "@angular/http";
import { AuthGuard } from "./security/auth.guard.service";
import {UtilityService} from "./utils.service";

@NgModule({
  imports: [
    HttpModule
  ],
  declarations: [
  ],
  exports: [
  ],
  providers: [
    AuthGuard,
    UtilityService
  ]
})
export class CoreModule {}
