import {Component, OnInit} from '@angular/core';
import {BasketService} from "./basket.service";
import {BasketData} from "./basket-data";
import { OAuthService } from 'angular-oauth2-oidc';
import {Router} from "@angular/router";
import {OrdersService} from "../orders/orders.service";

@Component({
  selector: 'basket',
  templateUrl: 'basket.component.html'
})

export class BasketComponent implements OnInit {

  basket: BasketData;

  private readonly basketService: BasketService;
  private readonly ordersService: OrdersService;
  private authService: OAuthService;
  private router: Router;

  constructor(
    basketService: BasketService,
    authService: OAuthService,
    ordersService: OrdersService,
    router: Router) {
    this.basketService = basketService;
    this.authService = authService;
    this.ordersService = ordersService;
    this.router = router;
    this.basket = new BasketData();
  }

  ngOnInit() {
    this.basketService.getBasket().subscribe((data) => {
        if(data.result !== null) {
          this.basket.copyFrom(data.result);
        }
      },
      (error) => {
        console.error(error);
      });
  }

  deleteCurrentBasket() {
    this.basketService.deleteBasket().subscribe((data) => {
        if(data) {
          if(data.result) {
            this.basket.basketItems = [];
          }
        }
      },
      (error) => {
        console.error(error);
      });
  }

  logout() {
    this.authService.logOut();
    this.router.navigate(['/login']);
  }

  checkoutOrder() {
    this.router.navigate(['/checkout']);
  }

  backToShop() {
    this.router.navigate(['/shop']);
  }
}
