/*
 * $Id$
 * Copyright (C) 2009 Lucid Fusion Labs

 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "core/app/app.h"
#include "core/web/dom.h"
#include "core/web/css.h"
#include "core/app/flow.h"
#include "core/app/gl/view.h"
#include "core/app/network.h"
#include "core/app/shell.h"

namespace LFL {
DEFINE_FLAG(sniff_device, int, 0, "Network interface index");

struct MyApp : public Application {
  using Application::Application;
  unique_ptr<Sniffer> sniffer;
  unique_ptr<GeoResolution> geo;
  void OnWindowInit(Window *W);
  void OnWindowStart(Window *W);
  void Sniff(const char *packet, int avail, int size);
} *app;

struct MyView : public View {
  Scene scene;
  MyView(Window *W) : View(W) {}

  int Frame(LFL::Window *W, unsigned clicks, int flag) {
    scene.Get("arrow")->YawRight((double)clicks/500);
    scene.Draw(W->gd, &app->asset.vec);

    // Press tick for console
    W->gd->DrawMode(DrawMode::_2D);
    W->DrawDialogs();
    return 0;
  }
};

void MyApp::Sniff(const char *packet, int avail, int size) {
  if (avail < Ethernet::Header::Size + IPV4::Header::MinSize) return;
  IPV4::Header *ip = (IPV4::Header*)(packet + Ethernet::Header::Size);
  int iphdrlen = ip->hdrlen() * 4;
  if (iphdrlen < IPV4::Header::MinSize || avail < Ethernet::Header::Size + iphdrlen) return;
  string src_ip = IPV4::Text(ip->src), dst_ip = IPV4::Text(ip->dst), src_city, dst_city;
  float src_lat, src_lng, dst_lat, dst_lng;
  geo->Resolve(src_ip, 0, 0, &src_city, &src_lat, &src_lng);
  geo->Resolve(dst_ip, 0, 0, &dst_city, &dst_lat, &dst_lng);

  if (ip->prot == 6 && avail >= Ethernet::Header::Size + iphdrlen + TCP::Header::MinSize) {
    TCP::Header *tcp = (TCP::Header*)((char*)ip + iphdrlen);
    INFO("TCP ", src_ip, ":", ntohs(tcp->src), " (", src_city, ") -> ", dst_ip, ":", ntohs(tcp->dst), " (", dst_city, ")");
  }
  else if (ip->prot == 17 && avail >= Ethernet::Header::Size + iphdrlen + UDP::Header::Size) {
    UDP::Header *udp = (UDP::Header*)((char*)ip + iphdrlen);
    INFO("UDP ", src_ip, ":", ntohs(udp->src), " -> ", dst_ip, ":", ntohs(udp->dst));
  }
  else INFO("ip ver=", ip->version(), " prot=", ip->prot, " ", src_ip, " -> ", dst_ip);
}

void MyApp::OnWindowInit(Window *W) {
  W->gl_w = 420;
  W->gl_h = 380;
  W->caption = "CrystalBawl";
}

void MyApp::OnWindowStart(Window *W) {
  CHECK_EQ(0, W->NewView());
  MyView *view = W->ReplaceView(0, make_unique<MyView>(W));
  W->frame_cb = bind(&MyView::Frame, view, _1, _2, _3);
  W->shell = make_unique<Shell>(W);
  BindMap *binds = W->AddInputController(make_unique<BindMap>());
  binds->Add(Key::Backquote, Bind::CB(bind(&Shell::console,         W->shell.get(), vector<string>())));
  binds->Add(Key::Quote,     Bind::CB(bind(&Shell::console,         W->shell.get(), vector<string>())));
  binds->Add(Key::Escape,    Bind::CB(bind(&Shell::quit,            W->shell.get(), vector<string>())));
  binds->Add(Key::Return,    Bind::CB(bind(&Shell::grabmode,        W->shell.get(), vector<string>())));
  binds->Add(Key::LeftShift, Bind::TimeCB(bind(&Entity::RollLeft,   &view->scene.cam, _1)));
  binds->Add(Key::Space,     Bind::TimeCB(bind(&Entity::RollRight,  &view->scene.cam, _1)));
  binds->Add('w',            Bind::TimeCB(bind(&Entity::MoveFwd,    &view->scene.cam, _1)));
  binds->Add('s',            Bind::TimeCB(bind(&Entity::MoveRev,    &view->scene.cam, _1)));
  binds->Add('a',            Bind::TimeCB(bind(&Entity::MoveLeft,   &view->scene.cam, _1)));
  binds->Add('d',            Bind::TimeCB(bind(&Entity::MoveRight,  &view->scene.cam, _1)));
  binds->Add('q',            Bind::TimeCB(bind(&Entity::MoveDown,   &view->scene.cam, _1)));
  binds->Add('e',            Bind::TimeCB(bind(&Entity::MoveUp,     &view->scene.cam, _1)));
}

}; // namespace LFL
using namespace LFL;

extern "C" LFApp *MyAppCreate(int argc, const char* const* argv) {
  FLAGS_enable_video = FLAGS_enable_input = FLAGS_enable_network = 1;
  FLAGS_target_fps = 50;
  FLAGS_threadpool_size = 1;
  app = make_unique<MyApp>(argc, argv).release();
  app->focused = CreateWindow(app).release();
  app->window_start_cb = bind(&MyApp::OnWindowStart, app, _1);
  app->window_init_cb = bind(&MyApp::OnWindowInit, app, _1);
  app->window_init_cb(app->focused);
  return app;
}

extern "C" int MyAppMain() {
  if (app->Create(__FILE__)) return -1;
  if (app->Init()) return -1;

  // app->asset.Add(name, texture,     scale, translate, rotate, geometry,                 nullptr, 0, 0);
  app->asset.Add(app, "axis",  "",          0,     0,         0,      nullptr,                  nullptr, 0, 0, Asset::DrawCB(bind(&glAxis, _1, _2, _3)));
  app->asset.Add(app, "grid",  "",          0,     0,         0,      Grid::Grid3D().release(), nullptr, 0, 0);
  app->asset.Add(app, "room",  "",          0,     0,         0,      nullptr,                  nullptr, 0, 0, Asset::DrawCB(bind(&glRoom, _1, _2, _3)));
  app->asset.Add(app, "arrow", "",         .005,   1,        -90,     "arrow.obj",              nullptr, 0);
  app->asset.Load();

  // app->soundassets.push_back(SoundAsset(name, filename,   ringbuf, channels, sample_rate, seconds));
  app->soundasset.Add(SoundAsset(app, "draw",  "Draw.wav", 0,       0,        0,           0      ));
  app->soundasset.Load();

  app->StartNewWindow(app->focused);
  MyView *view = app->focused->GetOwnView<MyView>(0);
  view->scene.Add(make_unique<Entity>("axis",  app->asset("axis")));
  view->scene.Add(make_unique<Entity>("grid",  app->asset("grid")));
  view->scene.Add(make_unique<Entity>("room",  app->asset("room")));
  view->scene.Add(make_unique<Entity>("arrow", app->asset("arrow"), v3(1, .24, 1)));

  vector<string> devices;
  Sniffer::PrintDevices(&devices);
  if (FLAGS_sniff_device < 0 || FLAGS_sniff_device >= devices.size()) FATAL(FLAGS_sniff_device, " oob ", devices.size(), ", are you running as root?");
  if (!(app->sniffer = Sniffer::Open(devices[FLAGS_sniff_device], "", 1024, bind(&MyApp::Sniff, app, _1, _2, _3)))) FATAL("sniffer Open failed");
  if (!(app->geo = GeoResolution::Open(StrCat(app->assetdir, "GeoLiteCity.dat").c_str()))) FATAL("geo Open failed");

  return app->Main();
}
