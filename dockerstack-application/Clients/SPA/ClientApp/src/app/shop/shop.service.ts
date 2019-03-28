import {Injectable} from '@angular/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import {environment} from "../../environments/environment";
import {HttpClient} from "@angular/common/http";

@Injectable()
export class ShopService {

  private http: HttpClient;

  constructor(http: HttpClient) {
    this.http = http;
  }

  getProducts() : Observable<any> {
    return this.http.get(environment.settings.catalog_gateway+ '/api/products');
  }
}
