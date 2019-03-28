import {RouterModule, Routes} from "@angular/router";
import {LoginComponent} from "./login/login.component";
import { ShopComponent } from "./shop/shop.component";
import { AuthGuard } from "./core/security/auth.guard.service";
import {NgModule} from "@angular/core";
import {OrdersComponent} from "./orders/orders.component";
import {BasketComponent} from "./basket/basket.component";

export const appRoutes: Routes = [
  {
    path: 'login',
    component: LoginComponent
  },
  {
    path: 'shop',
    component: ShopComponent,
    canActivate: [AuthGuard]
  },
  {
    path: 'checkout',
    component: OrdersComponent,
    canActivate: [AuthGuard]
  },
  {
    path: 'basket',
    component: BasketComponent,
    canActivate: [AuthGuard]
  },
  {
    path: '',
    component: LoginComponent
  },
  {
    path: '**',
    redirectTo: ''
  }
];

@NgModule({
  imports: [ RouterModule.forRoot(appRoutes) ],
  exports: [ RouterModule ]
})
export class AppRoutingModule {}
