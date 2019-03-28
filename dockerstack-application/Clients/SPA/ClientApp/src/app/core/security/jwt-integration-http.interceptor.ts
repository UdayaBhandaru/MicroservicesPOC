import {HttpEvent, HttpHandler, HttpInterceptor, HttpRequest} from "@angular/common/http";
import {Injectable, Injector} from "@angular/core";
import { Observable } from "rxjs/Observable";
import { OAuthService } from "angular-oauth2-oidc";
import {UtilityService} from "../utils.service";

/**
 * Add jwt in every http request
 */
@Injectable()
export class JwtIntegrationHttpInterceptor implements HttpInterceptor {

  constructor(private inj: Injector) { }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

    const auth = this.inj.get(OAuthService);

    if (auth.hasValidAccessToken()) {
      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${auth.getAccessToken()}`,
          RequestId: UtilityService.newGuid()
        }
      });
    }

    return next.handle(req)
  }
}
